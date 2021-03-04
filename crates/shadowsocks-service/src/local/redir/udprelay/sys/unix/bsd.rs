use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, UdpSocket},
    os::unix::io::AsRawFd,
    ptr,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{future::poll_fn, ready};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::{config::RedirType, local::redir::redir_ext::UdpSocketRedirExt, sys::sockaddr_to_std};

pub fn check_support_tproxy() -> io::Result<()> {
    Ok(())
}

pub struct UdpRedirSocket {
    io: AsyncFd<UdpSocket>,
}

impl UdpRedirSocket {
    /// Create a new UDP socket binded to `addr`
    ///
    /// This will allow listening to `addr` that is not in local host
    pub fn listen(ty: RedirType, addr: SocketAddr) -> io::Result<UdpRedirSocket> {
        UdpRedirSocket::bind(ty, addr, false)
    }

    /// Create a new UDP socket binded to `addr`
    ///
    /// This will allow binding to `addr` that is not in local host
    pub fn bind_nonlocal(ty: RedirType, addr: SocketAddr) -> io::Result<UdpRedirSocket> {
        UdpRedirSocket::bind(ty, addr, true)
    }

    fn bind(ty: RedirType, addr: SocketAddr, reuse_port: bool) -> io::Result<UdpRedirSocket> {
        if ty == RedirType::NotSupported {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "not supported udp transparent proxy type",
            ));
        }

        let domain = match addr {
            SocketAddr::V4(..) => Domain::ipv4(),
            SocketAddr::V6(..) => Domain::ipv6(),
        };
        let socket = Socket::new(domain, Type::dgram(), Some(Protocol::udp()))?;
        set_socket_before_bind(&addr, &socket)?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        if reuse_port {
            socket.set_reuse_port(true)?;
        }

        socket.bind(&SockAddr::from(addr))?;

        let io = AsyncFd::new(socket.into_udp_socket())?;
        Ok(UdpRedirSocket { io })
    }

    /// Send data to the socket to the given target address
    pub async fn send_to(&mut self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }

    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>> {
        loop {
            let mut write_guard = ready!(self.io.poll_write_ready(cx))?;

            match self.io.get_ref().send_to(buf, target) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    write_guard.clear_ready();
                }
                x => return Poll::Ready(x),
            }
        }
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }
}

impl UdpSocketRedir for UdpRedirSocket {
    fn poll_recv_dest_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr, SocketAddr)>> {
        loop {
            let mut read_guard = ready!(self.io.poll_read_ready(cx))?;

            match recv_dest_from(self.io.get_ref(), buf) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    read_guard.clear_ready();
                }
                x => return Poll::Ready(x),
            }
        }
    }
}

#[cfg(target_os = "freebsd")]
fn set_bindany(level: libc::c_int, socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;

    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE
    let opt = match level {
        libc::IPPROTO_IP => libc::IP_BINDANY,
        libc::IPPROTO_IPV6 => libc::IPV6_BINDANY,
        _ => unreachable!("level can only be IPPROTO_IP or IPPROTO_IPV6"),
    };

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

    Ok(())
}

#[cfg(target_os = "openbsd")]
fn set_bindany(_level: libc::c_int, socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;

    // https://man.openbsd.org/getsockopt.2
    let ret = libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_BINDANY,
        &enable as *const _ as *const _,
        mem::size_of_val(&enable) as libc::socklen_t,
    );
    if ret != 0 {
        return Err(Error::last_os_error());
    }

    Ok(())
}

fn set_socket_before_bind(addr: &SocketAddr, socket: &Socket) -> io::Result<()> {
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

fn recv_dest_from(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
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
        msg.msg_controllen = control_buf.len() as libc::size_t;

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
