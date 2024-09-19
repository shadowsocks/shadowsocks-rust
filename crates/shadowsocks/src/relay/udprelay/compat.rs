use async_trait::async_trait;
use std::{
    io::Result,
    net::SocketAddr,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

use crate::net::UdpSocket;

/// a trait for datagram transport that wraps around a tokio `UdpSocket`
#[async_trait]
pub trait DatagramTransport: Send + Sync + std::fmt::Debug {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    async fn send(&self, buf: &[u8]) -> Result<usize>;
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize>;

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<()>>;
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<SocketAddr>>;
    fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>>;

    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>>;
    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<Result<usize>>;
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>>;
}

#[async_trait]
impl DatagramTransport for UdpSocket {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        UdpSocket::recv(self, buf).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf).await
    }

    async fn send(&self, buf: &[u8]) -> Result<usize> {
        UdpSocket::send(self, buf).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize> {
        UdpSocket::send_to(self, buf, target).await
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<()>> {
        UdpSocket::poll_recv(self, cx, buf)
    }

    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<SocketAddr>> {
        UdpSocket::poll_recv_from(self, cx, buf)
    }

    fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        UdpSocket::poll_recv_ready(self, cx)
    }

    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        UdpSocket::poll_send(self, cx, buf)
    }

    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<Result<usize>> {
        UdpSocket::poll_send_to(self, cx, buf, target)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        UdpSocket::poll_send_ready(self, cx)
    }
}
