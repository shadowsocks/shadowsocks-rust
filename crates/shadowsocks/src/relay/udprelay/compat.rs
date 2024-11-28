use std::{
    future::Future,
    io,
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use pin_project::pin_project;
use tokio::io::ReadBuf;

use crate::net::UdpSocket;

/// A socket I/O object that can transport datagram
pub trait DatagramSocket {
    /// Local binded address
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// A socket I/O object that can receive datagram
pub trait DatagramReceive {
    /// `recv` data into `buf`
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>;
    /// `recv` data into `buf` with source address
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>>;
    /// Check if the underlying I/O object is ready for `recv`
    fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// A socket I/O object that can send datagram
pub trait DatagramSend {
    /// `send` data with `buf`, returning the sent bytes
    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;
    /// `send` data with `buf` to `target`, returning the sent bytes
    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>>;
    /// Check if the underlying I/O object is ready for `send`
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl DatagramSocket for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.deref().local_addr()
    }
}

impl DatagramReceive for UdpSocket {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        UdpSocket::poll_recv(self, cx, buf)
    }

    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        UdpSocket::poll_recv_from(self, cx, buf)
    }

    fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.deref().poll_recv_ready(cx)
    }
}

impl DatagramSend for UdpSocket {
    fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send(self, cx, buf)
    }

    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, buf, target)
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.deref().poll_send_ready(cx)
    }
}

/// Future for `recv`
#[pin_project]
pub struct RecvFut<'a, S: DatagramReceive + ?Sized> {
    #[pin]
    io: &'a S,
    buf: &'a mut [u8],
}

impl<S: DatagramReceive + ?Sized> Future for RecvFut<'_, S> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let mut read_buf = ReadBuf::new(this.buf);
        ready!(this.io.poll_recv(cx, &mut read_buf))?;
        Ok(read_buf.filled().len()).into()
    }
}

/// Future for `recv_from`
#[pin_project]
pub struct RecvFromFut<'a, S: DatagramReceive + ?Sized> {
    #[pin]
    io: &'a S,
    buf: &'a mut [u8],
}

impl<S: DatagramReceive + ?Sized> Future for RecvFromFut<'_, S> {
    type Output = io::Result<(usize, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let mut read_buf = ReadBuf::new(this.buf);
        let src_addr = ready!(this.io.poll_recv_from(cx, &mut read_buf))?;
        Ok((read_buf.filled().len(), src_addr)).into()
    }
}

/// Future for `recv_ready`
pub struct RecvReadyFut<'a, S: DatagramReceive + ?Sized> {
    io: &'a S,
}

impl<S: DatagramReceive + ?Sized> Future for RecvReadyFut<'_, S> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.io.poll_recv_ready(cx)
    }
}

/// Future for `send`
pub struct SendFut<'a, S: DatagramSend + ?Sized> {
    io: &'a S,
    buf: &'a [u8],
}

impl<S: DatagramSend + ?Sized> Future for SendFut<'_, S> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.io.poll_send(cx, self.buf)
    }
}

/// Future for `send_to`
pub struct SendToFut<'a, S: DatagramSend + ?Sized> {
    io: &'a S,
    target: SocketAddr,
    buf: &'a [u8],
}

impl<S: DatagramSend + ?Sized> Future for SendToFut<'_, S> {
    type Output = io::Result<usize>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.io.poll_send_to(cx, self.buf, self.target)
    }
}

/// Future for `recv_ready`
pub struct SendReadyFut<'a, S: DatagramSend + ?Sized> {
    io: &'a S,
}

impl<S: DatagramSend + ?Sized> Future for SendReadyFut<'_, S> {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.io.poll_send_ready(cx)
    }
}

/// Extension methods for `DatagramReceive`
pub trait DatagramReceiveExt: DatagramReceive {
    /// Async method for `poll_recv`
    fn recv<'a>(&'a self, buf: &'a mut [u8]) -> RecvFut<'a, Self> {
        RecvFut { io: self, buf }
    }

    /// Async method for `poll_recv_from`
    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> RecvFromFut<'a, Self> {
        RecvFromFut { io: self, buf }
    }

    /// Async method for `poll_recv_ready`
    fn recv_ready(&self) -> RecvReadyFut<'_, Self> {
        RecvReadyFut { io: self }
    }
}

impl<S: DatagramReceive> DatagramReceiveExt for S {}

/// Extension methods for `DatagramSend`
pub trait DatagramSendExt: DatagramSend {
    /// Async method for `poll_send`
    fn send<'a>(&'a self, buf: &'a [u8]) -> SendFut<'a, Self> {
        SendFut { io: self, buf }
    }

    /// Async method for `poll_send_to`
    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddr) -> SendToFut<'a, Self> {
        SendToFut { io: self, target, buf }
    }

    /// Async method for `poll_send_ready`
    fn send_ready(&self) -> SendReadyFut<'_, Self> {
        SendReadyFut { io: self }
    }
}

impl<S: DatagramSend> DatagramSendExt for S {}
