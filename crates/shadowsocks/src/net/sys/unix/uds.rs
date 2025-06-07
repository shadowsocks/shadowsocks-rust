//! Android specific features

use std::{
    io::{self, ErrorKind},
    os::unix::io::RawFd,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{future, ready};
use pin_project::pin_project;
use sendfd::{RecvWithFd, SendWithFd};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf},
    net::{UnixListener as TokioUnixListener, UnixStream as TokioUnixStream, unix::SocketAddr},
};

/// A UnixStream supports transferring FDs between processes
#[pin_project]
pub struct UnixStream {
    #[pin]
    io: TokioUnixStream,
}

impl UnixStream {
    /// Connects to the socket named by `path`.
    pub async fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        TokioUnixStream::connect(path).await.map(|io| Self { io })
    }

    fn poll_send_with_fd(&self, cx: &mut Context, buf: &[u8], fds: &[RawFd]) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_write_ready(cx))?;

            match self.io.try_io(Interest::WRITABLE, || self.io.send_with_fd(buf, fds)) {
                // self.io.poll_write_ready indicates that writable event have been received by tokio,
                // so it is not a common case that sendto returns EAGAIN.
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {}
                x => return Poll::Ready(x),
            }
        }
    }

    /// Send data with file descriptors
    pub async fn send_with_fd(&mut self, buf: &[u8], fds: &[RawFd]) -> io::Result<usize> {
        future::poll_fn(|cx| self.poll_send_with_fd(cx, buf, fds)).await
    }

    fn poll_recv_with_fd(
        &self,
        cx: &mut Context,
        buf: &mut [u8],
        fds: &mut [RawFd],
    ) -> Poll<io::Result<(usize, usize)>> {
        loop {
            ready!(self.io.poll_read_ready(cx))?;

            match self.io.try_io(Interest::READABLE, || self.io.recv_with_fd(buf, fds)) {
                // self.io.poll_write_ready indicates that writable event have been received by tokio,
                // so it is not a common case that recvto returns EAGAIN.
                //
                // Just for double check. If EAGAIN actually returns, clear the readiness state.
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {}
                x => return Poll::Ready(x),
            }
        }
    }

    /// Recv data with file descriptors
    pub async fn recv_with_fd(&mut self, buf: &mut [u8], fds: &mut [RawFd]) -> io::Result<(usize, usize)> {
        future::poll_fn(|cx| self.poll_recv_with_fd(cx, buf, fds)).await
    }
}

impl AsyncRead for UnixStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project().io.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().io.poll_shutdown(cx)
    }
}

/// A UnixListener supports transferring FDs between processes
pub struct UnixListener {
    io: TokioUnixListener,
}

impl UnixListener {
    /// Creates a new `UnixListener` bound to the specified socket.
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        TokioUnixListener::bind(path).map(|io| Self { io })
    }

    /// Accepts a new incoming connection to this listener.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(UnixStream, SocketAddr)>> {
        let (stream, peer_addr) = ready!(self.io.poll_accept(cx))?;
        Ok((UnixStream { io: stream }, peer_addr)).into()
    }

    /// Accepts a new incoming connection to this listener.
    pub async fn accept(&self) -> io::Result<(UnixStream, SocketAddr)> {
        future::poll_fn(|cx| self.poll_accept(cx)).await
    }
}
