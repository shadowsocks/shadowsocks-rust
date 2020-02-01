use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
    ptr,
};

use mio::net::UdpSocket;
use socket2::Socket;

use crate::relay::utils::sockaddr_to_std;

pub fn check_support_tproxy() -> io::Result<()> {
    Ok(())
}

fn set_bindany(level: libc::c_int, socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;

    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE
    let ret = libc::setsockopt(
        fd,
        level,
        libc::IP_BINDANY,
        &enable as *const _ as *const _,
        mem::size_of_val(&enable) as libc::socklen_t,
    );
    if ret != 0 {
        return Err(Error::last_os_error());
    }

    Ok(())
}

pub fn set_socket_before_bind(addr: &SocketAddr, socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;

    unsafe {
        // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE
        let (level, opt) = match *addr {
            SocketAddr::V4(..) => (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR),
            SocketAddr::V6(..) => (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR),
        };

        // 1. BINDANY
        set_bindany(level, socket)?;

        // 2. set ORIGDSTADDR for retrieving original destination address
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &enable as *const _ as *const _,
            mem::size_of_val(&enable) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

fn get_destination_addr(msg: &libc::msghdr) -> Option<libc::sockaddr_storage> {
    // https://www.freebsd.org/cgi/man.cgi?ip(4)
    //
    // Called `recvmsg` with `IP_ORIGDSTADDR` set

    unsafe {
        let mut cmsg: *mut libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let rcmsg = &*cmsg;
            match (rcmsg.cmsg_level, rcmsg.cmsg_type) {
                (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = mem::zeroed();

                    ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        mem::size_of::<libc::sockaddr_in>(),
                    );

                    return Some(dst_addr);
                }
                (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = mem::zeroed();

                    ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        mem::size_of::<libc::sockaddr_in6>(),
                    );

                    return Some(dst_addr);
                }
                _ => {}
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }

    None
}

pub fn recv_from_with_destination(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut control_buf = [0u8; 64];
        let mut src_addr: libc::sockaddr_storage = mem::zeroed();

        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = &mut src_addr as *mut _ as *mut _;
        msg.msg_namelen = mem::size_of_val(&src_addr) as libc::socklen_t;

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len() as libc::size_t,
        };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        msg.msg_control = control_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = control_buf.len() as libc::socklen_t;

        let fd = socket.as_raw_fd();
        let ret = libc::recvmsg(fd, &mut msg, 0);
        if ret < 0 {
            return Err(Error::last_os_error());
        }

        let dst_addr = match get_destination_addr(&msg) {
            None => {
                let err = Error::new(ErrorKind::InvalidData, "missing destination address in msghdr");
                return Err(err);
            }
            Some(d) => d,
        };

        Ok((ret as usize, sockaddr_to_std(&src_addr)?, sockaddr_to_std(&dst_addr)?))
    }
}
