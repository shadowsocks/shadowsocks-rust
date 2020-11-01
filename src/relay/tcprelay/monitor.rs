//! Server traffic monitor

use std::{
    io,
    marker::Unpin,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::relay::flow::SharedServerFlowStatistic;

#[pin_project]
pub struct TcpMonStream<S> {
    #[pin]
    stream: S,
    flow_stat: SharedServerFlowStatistic,
}

impl<S> TcpMonStream<S> {
    pub fn new(flow_stat: SharedServerFlowStatistic, stream: S) -> TcpMonStream<S> {
        TcpMonStream { stream, flow_stat }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> AsyncRead for TcpMonStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();

        let before_remain = buf.remaining();
        ready!(this.stream.poll_read(cx, buf))?;
        this.flow_stat.tcp().incr_rx(before_remain - buf.remaining());
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for TcpMonStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.project();

        let n = match this.stream.poll_write(cx, buf)? {
            Poll::Ready(n) => n,
            Poll::Pending => return Poll::Pending,
        };
        this.flow_stat.tcp().incr_tx(n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
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
