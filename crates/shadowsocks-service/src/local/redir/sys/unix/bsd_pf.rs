//! PacketFilter implementation for *BSD

use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    ptr,
};

use cfg_if::cfg_if;
use log::trace;
use nix::ioctl_readwrite;
use once_cell::sync::Lazy;
use socket2::{Protocol, SockAddr};

use super::pfvar::{in6_addr, in_addr, pfioc_natlook, sockaddr_in, sockaddr_in6, PF_OUT};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use super::pfvar::{pf_addr, pfioc_states, pfsync_state};

ioctl_readwrite!(ioc_natlook, 'D', 23, pfioc_natlook);
#[cfg(any(target_os = "macos", target_os = "ios"))]
ioctl_readwrite!(ioc_getstates, 'D', 25, pfioc_states);

pub struct PacketFilter {
    fd: libc::c_int,
}

impl PacketFilter {
    fn open() -> io::Result<PacketFilter> {
        unsafe {
            let dev_path = b"/dev/pf\0";

            // According to FreeBSD's doc
            // https://www.freebsd.org/cgi/man.cgi?query=pf&sektion=4&apropos=0&manpath=FreeBSD+12.1-RELEASE+and+Ports
            let fd = libc::open(dev_path.as_ptr() as *const _, libc::O_RDONLY);
            if fd < 0 {
                let err = Error::last_os_error();
                return Err(err);
            }

            // Set CLOEXEC
            let ret = libc::fcntl(fd, libc::F_SETFD, libc::fcntl(fd, libc::F_GETFD) | libc::FD_CLOEXEC);
            if ret != 0 {
                let err = Error::last_os_error();
                let _ = libc::close(fd);
                return Err(err);
            }

            Ok(PacketFilter { fd })
        }
    }

    pub fn natlook(&self, bind_addr: &SocketAddr, peer_addr: &SocketAddr, proto: Protocol) -> io::Result<SocketAddr> {
        match proto {
            Protocol::TCP => self.tcp_natlook(bind_addr, peer_addr, proto),
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            Protocol::UDP => self.udp_natlook(bind_addr, peer_addr, proto),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }

    fn tcp_natlook(&self, bind_addr: &SocketAddr, peer_addr: &SocketAddr, proto: Protocol) -> io::Result<SocketAddr> {
        trace!("PF natlook peer: {}, bind: {}", peer_addr, bind_addr);

        unsafe {
            let mut pnl: pfioc_natlook = mem::zeroed();

            match *bind_addr {
                SocketAddr::V4(ref v4) => {
                    pnl.af = libc::AF_INET as libc::sa_family_t;

                    let sockaddr = SockAddr::from(*v4);
                    let sockaddr = sockaddr.as_ptr() as *const sockaddr_in;

                    let addr: *const in_addr = ptr::addr_of!((*sockaddr).sin_addr) as *const _;
                    let port: libc::in_port_t = (*sockaddr).sin_port;

                    ptr::write_unaligned::<in_addr>(ptr::addr_of_mut!(pnl.daddr.pfa) as *mut _, *addr);

                    cfg_if! {
                        if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                            pnl.dxport.port = port;
                        } else {
                            pnl.dport = port;
                        }
                    }
                }
                SocketAddr::V6(ref v6) => {
                    pnl.af = libc::AF_INET6 as libc::sa_family_t;

                    let sockaddr = SockAddr::from(*v6);
                    let sockaddr = sockaddr.as_ptr() as *const sockaddr_in6;

                    let addr: *const in6_addr = ptr::addr_of!((*sockaddr).sin6_addr) as *const _;
                    let port: libc::in_port_t = (*sockaddr).sin6_port;

                    ptr::write_unaligned::<in6_addr>(ptr::addr_of_mut!(pnl.daddr.pfa) as *mut _, *addr);

                    cfg_if! {
                        if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                            pnl.dxport.port = port;
                        } else {
                            pnl.dport = port;
                        }
                    }
                }
            }

            match *peer_addr {
                SocketAddr::V4(ref v4) => {
                    if pnl.af != libc::AF_INET as libc::sa_family_t {
                        return Err(Error::new(ErrorKind::InvalidInput, "client addr must be ipv4"));
                    }

                    let sockaddr = SockAddr::from(*v4);
                    let sockaddr = sockaddr.as_ptr() as *const sockaddr_in;

                    let addr: *const in_addr = ptr::addr_of!((*sockaddr).sin_addr) as *const _;
                    let port: libc::in_port_t = (*sockaddr).sin_port;

                    ptr::write_unaligned::<in_addr>(ptr::addr_of_mut!(pnl.saddr.pfa) as *mut _, *addr);

                    cfg_if! {
                        if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                            pnl.sxport.port = port;
                        } else {
                            pnl.sport = port;
                        }
                    }
                }
                SocketAddr::V6(ref v6) => {
                    if pnl.af != libc::AF_INET6 as libc::sa_family_t {
                        return Err(Error::new(ErrorKind::InvalidInput, "client addr must be ipv6"));
                    }

                    let sockaddr = SockAddr::from(*v6);
                    let sockaddr = sockaddr.as_ptr() as *const sockaddr_in6;

                    let addr: *const in6_addr = ptr::addr_of!((*sockaddr).sin6_addr) as *const _;
                    let port: libc::in_port_t = (*sockaddr).sin6_port;

                    ptr::write_unaligned::<in6_addr>(ptr::addr_of_mut!(pnl.saddr.pfa) as *mut _, *addr);

                    cfg_if! {
                        if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                            pnl.sxport.port = port;
                        } else {
                            pnl.sport = port;
                        }
                    }
                }
            }

            pnl.proto = i32::from(proto) as u8;
            pnl.direction = PF_OUT as u8;

            if let Err(err) = ioc_natlook(self.fd, &mut pnl) {
                return Err(Error::from_raw_os_error(err as i32));
            }

            let (_, dst_addr) = SockAddr::try_init(|dst_addr, addr_len| {
                if pnl.af == libc::AF_INET as libc::sa_family_t {
                    let dst_addr: &mut sockaddr_in = &mut *(dst_addr as *mut _);
                    dst_addr.sin_family = pnl.af;

                    cfg_if! {
                        if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                            dst_addr.sin_port = pnl.rdxport.port;
                        } else {
                            dst_addr.sin_port = pnl.rdport;
                        }
                    }

                    ptr::write_unaligned::<in_addr>(
                        ptr::addr_of_mut!(dst_addr.sin_addr),
                        ptr::read::<in_addr>(ptr::addr_of!(pnl.rdaddr.pfa) as *const _),
                    );
                    *addr_len = mem::size_of_val(&dst_addr.sin_addr) as libc::socklen_t;
                } else if pnl.af == libc::AF_INET6 as libc::sa_family_t {
                    let dst_addr: &mut sockaddr_in6 = &mut *(dst_addr as *mut _);
                    dst_addr.sin6_family = pnl.af;

                    cfg_if! {
                        if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                            dst_addr.sin6_port = pnl.rdxport.port;
                        } else {
                            dst_addr.sin6_port = pnl.rdport;
                        }
                    }

                    ptr::write_unaligned::<in6_addr>(
                        ptr::addr_of_mut!(dst_addr.sin6_addr),
                        ptr::read::<in6_addr>(ptr::addr_of!(pnl.rdaddr.pfa) as *const _),
                    );
                    *addr_len = mem::size_of_val(&dst_addr.sin6_addr) as libc::socklen_t;
                } else {
                    unreachable!("sockaddr should be either ipv4 or ipv6");
                }

                Ok(())
            })?;

            Ok(dst_addr.as_socket().expect("SocketAddr"))
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn udp_natlook(&self, bind_addr: &SocketAddr, peer_addr: &SocketAddr, _proto: Protocol) -> io::Result<SocketAddr> {
        unsafe {
            // Get all states
            // https://man.freebsd.org/cgi/man.cgi?query=pf&sektion=4&manpath=OpenBSD
            // DIOCGETSTATES

            let mut states: pfioc_states = mem::zeroed();
            let mut states_buffer = vec![0u8; 8192];

            loop {
                states.ps_len = states_buffer.len() as _;
                states.ps_u.psu_buf = states_buffer.as_mut_ptr() as *mut _;

                if let Err(err) = ioc_getstates(self.fd, &mut states) {
                    return Err(Error::from_raw_os_error(err as i32));
                }

                if states.ps_len as usize <= states_buffer.len() {
                    break;
                }

                // Resize to fit all states
                // > On exit, ps_len is always set to the total size re-
                // > quired to hold all state table entries
                states_buffer.resize(states.ps_len as usize, 0);
            }

            let bind_addr_sockaddr = SockAddr::from(*bind_addr);
            let peer_addr_sockaddr = SockAddr::from(*peer_addr);

            let mut bind_addr_pfaddr: pf_addr = mem::zeroed();
            let mut peer_addr_pfaddr: pf_addr = mem::zeroed();

            match bind_addr_sockaddr.family() as libc::c_int {
                libc::AF_INET => {
                    let sockaddr: *const sockaddr_in = bind_addr_sockaddr.as_ptr() as *const _;
                    ptr::write_unaligned::<in_addr>(
                        ptr::addr_of_mut!(bind_addr_pfaddr.pfa) as *mut _,
                        (*sockaddr).sin_addr,
                    );
                }
                libc::AF_INET6 => {
                    let sockaddr: *const sockaddr_in6 = bind_addr_sockaddr.as_ptr() as *const _;
                    ptr::write_unaligned::<in6_addr>(
                        ptr::addr_of_mut!(bind_addr_pfaddr.pfa) as *mut _,
                        (*sockaddr).sin6_addr,
                    );
                }
                _ => unreachable!("bind_addr family = {}", bind_addr_sockaddr.family()),
            }

            match peer_addr_sockaddr.family() as libc::c_int {
                libc::AF_INET => {
                    let sockaddr: *const sockaddr_in = peer_addr_sockaddr.as_ptr() as *const _;
                    ptr::write_unaligned::<in_addr>(
                        ptr::addr_of_mut!(peer_addr_pfaddr.pfa) as *mut _,
                        (*sockaddr).sin_addr,
                    );
                }
                libc::AF_INET6 => {
                    let sockaddr: *const sockaddr_in6 = peer_addr_sockaddr.as_ptr() as *const _;
                    ptr::write_unaligned::<in6_addr>(
                        ptr::addr_of_mut!(peer_addr_pfaddr.pfa) as *mut _,
                        (*sockaddr).sin6_addr,
                    );
                }
                _ => unreachable!("peer_addr family = {}", peer_addr_sockaddr.family()),
            }

            let states_count = states.ps_len as usize / mem::size_of::<pfsync_state>();
            for i in 0..states_count {
                let state = &*(states.ps_u.psu_states.add(i));

                if state.proto == libc::IPPROTO_UDP as u8 {
                    cfg_if! {
                        if #[cfg(any(target_os = "macos", target_os = "ios"))] {
                            let dst_port = state.lan.xport.port;
                            let src_port = state.ext_gwy.xport.port;
                            let actual_dst_port = state.gwy.xport.port;
                        } else {
                            let dst_port = state.lan.port;
                            let src_port = state.ext_gwy.port;
                            let actual_dst_port = state.gwy.port;
                        }
                    }

                    let dst_addr_eq = libc::memcmp(
                        &bind_addr_pfaddr as *const _ as *const _,
                        ptr::addr_of!(state.lan.addr.pfa) as *const _,
                        mem::size_of::<pf_addr>(),
                    ) == 0;
                    let src_addr_eq = libc::memcmp(
                        &peer_addr_pfaddr as *const _ as *const _,
                        ptr::addr_of!(state.ext_gwy.addr.pfa) as *const _,
                        mem::size_of::<pf_addr>(),
                    ) == 0;

                    if src_addr_eq && src_port == peer_addr.port() && dst_addr_eq && dst_port == bind_addr.port() {
                        let actual_dst_addr = match state.af_gwy as libc::c_int {
                            libc::AF_INET => {
                                let (_, actual_dst_addr) = SockAddr::try_init(|sockaddr, len| {
                                    let addr = &mut *(sockaddr as *mut sockaddr_in);
                                    addr.sin_family = libc::AF_INET as libc::sa_family_t;
                                    ptr::write_unaligned::<in_addr>(
                                        ptr::addr_of_mut!(addr.sin_addr),
                                        ptr::read_unaligned::<in_addr>(ptr::addr_of!(state.gwy.addr.pfa) as *const _),
                                    );
                                    addr.sin_port = actual_dst_port as libc::in_port_t;

                                    ptr::write(len, mem::size_of::<sockaddr_in>() as libc::socklen_t);
                                    Ok(())
                                })
                                .unwrap();

                                actual_dst_addr
                            }
                            libc::AF_INET6 => {
                                let (_, actual_dst_addr) = SockAddr::try_init(|sockaddr, len| {
                                    let addr = &mut *(sockaddr as *mut sockaddr_in6);
                                    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                                    ptr::write_unaligned::<in6_addr>(
                                        ptr::addr_of_mut!(addr.sin6_addr),
                                        ptr::read_unaligned::<in6_addr>(ptr::addr_of!(state.gwy.addr.pfa) as *const _),
                                    );
                                    addr.sin6_port = actual_dst_port as libc::in_port_t;

                                    ptr::write(len, mem::size_of::<sockaddr_in6>() as libc::socklen_t);
                                    Ok(())
                                })
                                .unwrap();

                                actual_dst_addr
                            }
                            _ => {
                                return Err(io::Error::new(
                                    ErrorKind::Other,
                                    format!("state.af_gwy {} is not a valid address family", state.af_gwy),
                                ));
                            }
                        };

                        return Ok(actual_dst_addr.as_socket().expect("SocketAddr"));
                    }
                }
            }
        }

        Err(io::Error::new(
            ErrorKind::Other,
            format!("natlook UDP binding {}, {} not found", bind_addr, peer_addr),
        ))
    }
}

impl Drop for PacketFilter {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

pub static PF: Lazy<PacketFilter> = Lazy::new(|| match PacketFilter::open() {
    Ok(pf) => pf,
    Err(err) if err.kind() == ErrorKind::PermissionDenied => {
        panic!("open /dev/pf permission denied, consider restart with root user");
    }
    Err(err) => {
        panic!("open /dev/pf {err}");
    }
});
