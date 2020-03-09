//! Extensions for redir (transparent proxy)

use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::TcpStream;

#[async_trait]
pub trait TcpListenerRedirExt {
    /// Accept clients with its original destination addresss
    ///
    /// Works very similar to `TcpListen::accept`, but returns
    ///
    /// 1. A `TcpStream`, the accepted socket
    /// 2. Peer address
    /// 3. Original destination address
    async fn accept_redir(&mut self) -> io::Result<(TcpStream, SocketAddr, Option<SocketAddr>)>;
}

#[async_trait]
pub trait UdpSocketRedirExt {
    /// Receive a single datagram from the socket.
    ///
    /// On success, the future resolves to the number of bytes read and the source, target address
    ///
    /// `(bytes read, source address, target address)`
    async fn recv_from_redir(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)>;
}
