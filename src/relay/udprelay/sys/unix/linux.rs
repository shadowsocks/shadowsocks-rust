use std::{
    convert::TryFrom,
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
    ptr,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{future::poll_fn, ready};
use mio::net::UdpSocket;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::PollEvented;

use crate::{
    config::RedirType,
    relay::{redir::UdpSocketRedirExt, sys::sockaddr_to_std},
};

pub struct UdpRedirSocket {
    io: PollEvented<mio::net::UdpSocket>,
}

impl UdpRedirSocket {
    /// Create a new UDP socket binded to `addr`
    ///
    /// This will allow binding to `addr` that is not in local host
    pub fn bind(ty: RedirType, addr: &SocketAddr) -> io::Result<UdpRedirSocket> {
        if ty != RedirType::TProxy {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "not supported udp transparent proxy type",
            ));
        }

        let domain = match *addr {
            SocketAddr::V4(..) => Domain::ipv4(),
            SocketAddr::V6(..) => Domain::ipv6(),
        };
        let socket = Socket::new(domain, Type::dgram(), Some(Protocol::udp()))?;
        set_socket_before_bind(addr, &socket)?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;

        socket.bind(&SockAddr::from(*addr))?;

        let msock = mio::net::UdpSocket::from_socket(socket.into_udp_socket())?;
        let io = PollEvented::new(msock)?;
        Ok(UdpRedirSocket { io })
    }

    /// Send data to the socket to the given target address
    pub async fn send_to(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }

    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: &SocketAddr) -> Poll<io::Result<usize>> {
        ready!(self.io.poll_write_ready(cx))?;

        match self.io.get_ref().send_to(buf, target) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr, SocketAddr)>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;

        match recv_from_with_destination(self.io.get_ref(), buf) {
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                self.io.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            x => Poll::Ready(x),
        }
    }
}

#[async_trait]
impl UdpSocketRedirExt for UdpRedirSocket {
    async fn recv_from_redir(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }
}

fn set_socket_before_bind(addr: &SocketAddr, socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;
    unsafe {
        // 1. Set IP_TRANSPARENT to allow binding to non-local addresses
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &enable as *const _ as *const _,
            mem::size_of_val(&enable) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(Error::last_os_error());
        }

        // 2. Set IP_RECVORIGDSTADDR, IPV6_RECVORIGDSTADDR
        let ret = match *addr {
            SocketAddr::V4(..) => libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_RECVORIGDSTADDR,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
            SocketAddr::V6(..) => libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
        };
        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

fn get_destination_addr(msg: &libc::msghdr) -> Option<libc::sockaddr_storage> {
    unsafe {
        let mut cmsg: *mut libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let rcmsg = &*cmsg;
            match (rcmsg.cmsg_level, rcmsg.cmsg_type) {
                (libc::SOL_IP, libc::IP_RECVORIGDSTADDR) => {
                    let mut dst_addr: libc::sockaddr_storage = mem::zeroed();

                    ptr::copy(
                        libc::CMSG_DATA(cmsg),
                        &mut dst_addr as *mut _ as *mut _,
                        mem::size_of::<libc::sockaddr_in>(),
                    );

                    return Some(dst_addr);
                }
                (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR) => {
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
        // This is f*** s***, some platform define msg_controllen as size_t, some define as u32
        msg.msg_controllen = TryFrom::try_from(control_buf.len()).expect("failed to convert usize to msg_controllen");

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
