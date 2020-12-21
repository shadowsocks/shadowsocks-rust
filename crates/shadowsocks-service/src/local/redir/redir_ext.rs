//! Extension trait for `TcpListener` and `UdpSocket`

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::net::TcpListener;

use crate::config::RedirType;

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

pub trait UdpSocketRedir {
    /// Receive a single datagram from the socket.
    ///
    /// On success, the future resolves to the number of bytes read and the source, target address
    ///
    /// `(bytes read, source address, target address)`
    fn poll_recv_from_with_destination(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr, SocketAddr)>>;
}

pub trait UdpSocketRedirExt {
    fn recv_from_with_destination<'a>(&'a self, buf: &'a mut [u8]) -> RecvFromWithDestination<'a, Self>
    where
        Self: Sized,
    {
        RecvFromWithDestination { socket: self, buf }
    }
}

impl<S> UdpSocketRedirExt for S where S: UdpSocketRedir {}

pub struct RecvFromWithDestination<'a, S: 'a> {
    socket: &'a S,
    buf: &'a mut [u8],
}

impl<'a, S: 'a> Future for RecvFromWithDestination<'a, S>
where
    S: UdpSocketRedir,
{
    type Output = io::Result<(usize, SocketAddr, SocketAddr)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.socket.poll_recv_from_with_destination(cx, self.buf)
    }
}
