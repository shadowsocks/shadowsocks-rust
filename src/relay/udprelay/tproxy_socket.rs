//! Socket for supporting TPROXY

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    task::{Context, Poll},
};

use futures::{future::poll_fn, ready};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::PollEvented;

use super::sys::{check_support_tproxy, recv_from_with_destination, set_socket_before_bind};

/// A socket interface for transparent proxy
///
/// It has basically the same APIs like `tokio::net::UdpSocket`,
/// but `recv_from` will return destination address of UDP packet
pub struct TProxyUdpSocket {
    io: PollEvented<mio::net::UdpSocket>,
}

impl TProxyUdpSocket {
    /// Create a new UDP socket binded to `addr`
    ///
    /// This will allow binding to `addr` that is not in local host
    pub fn bind(addr: &SocketAddr) -> io::Result<TProxyUdpSocket> {
        // Check if current plaform supports TPROXY (UDP)
        // This is a runtime error.
        check_support_tproxy()?;

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
        Ok(TProxyUdpSocket { io })
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

    /// Receive a single datagram from the socket.
    ///
    /// On success, the future resolves to the number of bytes read and the origin, target address
    ///
    /// `(bytes read, origin address, target address)`
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
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
