//! Server traffic monitor

use std::{
    io::{self, Read, Write},
    marker::Unpin,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use super::context::SharedTcpServerContext;

pub struct TcpMonStream<S> {
    stream: S,
    context: SharedTcpServerContext,
}

impl<S> TcpMonStream<S> {
    pub fn new(c: SharedTcpServerContext, s: S) -> TcpMonStream<S> {
        TcpMonStream { stream: s, context: c }
    }
}

impl<S> AsyncRead for TcpMonStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let n = match Pin::new(&mut self.stream).poll_read(cx, buf)? {
            Poll::Ready(n) => n,
            Poll::Pending => return Poll::Pending,
        };
        self.context.incr_rx(n);
        Poll::Ready(Ok(n))
    }
}

impl<S> AsyncWrite for TcpMonStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let n = match Pin::new(&mut self.stream).poll_write(cx, buf)? {
            Poll::Ready(n) => n,
            Poll::Pending => return Poll::Pending,
        };
        self.context.incr_tx(n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<S> Deref for TcpMonStream<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<S> DerefMut for TcpMonStream<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}
