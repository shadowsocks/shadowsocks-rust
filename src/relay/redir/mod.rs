//! Extensions for redir (transparent proxy)

use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tokio::net::TcpListener;

use crate::config::RedirType;

pub mod sys;

#[async_trait]
pub trait TcpListenerRedirExt {
    // Create a TcpListener for transparent proxy
    //
    // Implementation is platform dependent
    async fn bind_redir(ty: RedirType, addr: SocketAddr) -> io::Result<TcpListener>;
}

pub trait TcpStreamRedirExt {
    // Read destination address for TcpStream
    //
    // Implementation is platform dependent
    fn destination_addr(&self, ty: RedirType) -> io::Result<SocketAddr>;
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
