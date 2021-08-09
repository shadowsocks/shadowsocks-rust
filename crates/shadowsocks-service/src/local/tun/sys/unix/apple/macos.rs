use std::{
    ffi::CStr,
    io::{self, ErrorKind},
    mem,
    ptr,
};

use log::{error, trace};
use tun::{platform::Device as TunDevice, Device};

/// These numbers are used by reliable protocols for determining
/// retransmission behavior and are included in the routing structure.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
struct rt_metrics {
    rmx_locks: u32,       //< Kernel must leave these values alone
    rmx_mtu: u32,         //< MTU for this path
    rmx_hopcount: u32,    //< max hops expected
    rmx_expire: i32,      //< lifetime for route, e.g. redirect
    rmx_recvpipe: u32,    //< inbound delay-bandwidth product
    rmx_sendpipe: u32,    //< outbound delay-bandwidth product
    rmx_ssthresh: u32,    //< outbound gateway buffer limit
    rmx_rtt: u32,         //< estimated round trip time
    rmx_rttvar: u32,      //< estimated rtt variance
    rmx_pksent: u32,      //< packets sent using this route
    rmx_state: u32,       //< route state
    rmx_filler: [u32; 3], //< will be used for T/TCP later
}

/// Structures for routing messages.
#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
struct rt_msghdr {
    rtm_msglen: libc::c_ushort, //< to skip over non-understood messages
    rtm_version: libc::c_uchar, //< future binary compatibility
    rtm_type: libc::c_uchar,    //< message type
    rtm_index: libc::c_ushort,  //< index for associated ifp
    rtm_flags: libc::c_int,     //< flags, incl. kern & message, e.g. DONE
    rtm_addrs: libc::c_int,     //< bitmask identifying sockaddrs in msg
    rtm_pid: libc::pid_t,       //< identify sender
    rtm_seq: libc::c_int,       //< for sender to identify action
    rtm_errno: libc::c_int,     //< why failed
    rtm_use: libc::c_int,       //< from rtentry
    rtm_inits: u32,             //< which metrics we are initializing
    rtm_rmx: rt_metrics,        //< metrics themselves
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
struct rt_msg {
    rtm: rt_msghdr,
    dst: libc::sockaddr_in,
    gateway: libc::sockaddr_dl,
    netmask: libc::sockaddr_in,
}

/// Set platform specific route configuration
pub async fn set_route_configuration(device: &TunDevice) -> io::Result<()> {
    let tun_address = match device.address() {
        Ok(t) => t,
        Err(err) => {
            error!("tun device doesn't have address, error: {}", err);
            return Err(io::Error::new(ErrorKind::Other, err));
        }
    };

    let tun_netmask = match device.netmask() {
        Ok(m) => m,
        Err(err) => {
            error!("tun device doesn't have netmask, error: {}", err);
            return Err(io::Error::new(ErrorKind::Other, err));
        }
    };

    let tun_name = device.name();

    // routing packets that saddr & daddr are in the subnet of the Tun interface
    //
    // This is only required for the TCP tunnel, and it is the default behavior on Linux
    //
    // https://opensource.apple.com/source/network_cmds/network_cmds-307.0.1/route.tproj/route.c.auto.html

    unsafe {
        let mut rtmsg: rt_msg = mem::zeroed();
        rtmsg.rtm.rtm_type = libc::RTM_ADD as libc::c_uchar;
        rtmsg.rtm.rtm_flags = libc::RTF_UP | libc::RTF_STATIC;
        rtmsg.rtm.rtm_version = libc::RTM_VERSION as libc::c_uchar;
        rtmsg.rtm.rtm_seq = rand::random();
        rtmsg.rtm.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK;
        rtmsg.rtm.rtm_msglen = mem::size_of_val(&rtmsg) as libc::c_ushort;
        rtmsg.rtm.rtm_pid = libc::getpid();

        // Set address as destination addr
        {
            rtmsg.dst.sin_family = libc::AF_INET as libc::sa_family_t;
            rtmsg.dst.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(tun_address.octets()),
            };
            rtmsg.dst.sin_len = mem::size_of_val(&rtmsg.dst) as u8;
        }

        // Get the interface's link address (sockaddr_dl)
        let found_gateway = {
            let mut found_ifaddr = false;

            let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                return Err(io::Error::last_os_error());
            }

            let mut ifa = ifap;
            while !ifa.is_null() {
                if !(*ifa).ifa_addr.is_null() && (*(*ifa).ifa_addr).sa_family as i32 == libc::AF_LINK {
                    let ifa_name = CStr::from_ptr((*ifa).ifa_name);
                    if ifa_name.to_bytes() == tun_name.as_bytes() {
                        // Found the link_addr of tun interface.

                        let sdl: *mut libc::sockaddr_dl = (*ifa).ifa_addr as *mut _;
                        rtmsg.gateway = *sdl;

                        found_ifaddr = true;
                        break;
                    }
                }

                ifa = (*ifa).ifa_next;
            }
            libc::freeifaddrs(ifap);

            found_ifaddr
        };

        if !found_gateway {
            error!("couldn't get interface \"{}\" AF_LINK address", tun_name);
            return Err(io::Error::new(
                ErrorKind::Other,
                "couldn't get interface AF_LINK address",
            ));
        }

        // netmask
        {
            rtmsg.netmask.sin_family = libc::AF_INET as libc::sa_family_t;
            rtmsg.netmask.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(tun_netmask.octets()),
            };
            rtmsg.netmask.sin_len = mem::size_of_val(&rtmsg.netmask) as u8;
        }

        trace!("add route {:?}", rtmsg);

        let fd = libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let n = libc::write(fd, &mut rtmsg as *mut _ as *mut _, mem::size_of_val(&rtmsg));
        if n < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }

        libc::close(fd);
    }

    Ok(())
}
