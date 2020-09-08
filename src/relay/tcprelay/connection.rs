//! TCP Connection with timeout

use std::{
    future::Future,
    io::{self},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::ready;
use log::error;
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, ReadHalf, WriteHalf},
    net::TcpStream,
    time::{self, Delay},
};

/// Methods required for a TCP Connection
pub trait TcpConnection {
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
}

impl TcpConnection for TcpStream {
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, nodelay)
    }
}

/// Shadowsocks' Connection
///
/// The only feature: Supports timeout
#[pin_project]
pub struct Connection<S> {
    // Actual connection socket
    #[pin]
    stream: BufReader<S>,
    // Timer instance
    // Read and Write operations shares the same timer
    timer: Option<Delay>,
    // User defined server timeout
    timeout: Option<Duration>,
    // TCP_NODELAY
    nodelay: bool,
    // Written the first packet flag
    //
    // Connection is usually wrapped inside a `CryptoStream`, which will send IV/Nonce within the first data packet.
    // `TCP_NODELAY` is already set on the internal socket for lower handshake latency.
    //
    // After the first packet, if `nodelay` is `false`, `TCP_NODELAY` status should be reset.
    written_first_packet: bool,
}

impl<S> Connection<S>
where
    S: AsyncRead + TcpConnection,
{
    /// Create a Connection with a stream S
    ///
    /// If `timeout` is Some(..), it will set a timer for both read and write operation.
    pub fn new(stream: S, timeout: Option<Duration>) -> Connection<S> {
        // Set `TCP_NODELAY` for quick handshaking
        if let Err(err) = stream.set_nodelay(true) {
            error!("failed to set TCP_NODELAY on socket, error: {:?}", err);
        }

        Connection {
            stream: BufReader::new(stream),
            timer: None,
            timeout,
            nodelay: false,
            written_first_packet: false,
        }
    }

    /// Set `TCP_NODELAY` on socket
    pub fn set_nodelay(&mut self, nodelay: bool) -> io::Result<()> {
        self.nodelay = nodelay;

        // If first packet hasn't sent, resetting nodelay is delayed
        if self.written_first_packet {
            self.stream.get_ref().set_nodelay(nodelay)?;
        }

        Ok(())
    }

    /// Get a reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    /// Get the internal stream and consume this Connection
    pub fn into_inner(self) -> S {
        self.stream.into_inner()
    }
}

#[inline]
fn make_timeout_error() -> io::Error {
    use std::io::ErrorKind;
    ErrorKind::TimedOut.into()
}

impl<S> Connection<S> {
    fn poll_timeout(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut timer) = self.timer {
                ready!(Pin::new(timer).poll(cx));
                // FIXME: Clear self.timer or not?
                return Poll::Ready(Err(make_timeout_error()));
            } else {
                match self.timeout {
                    Some(timeout) => self.timer = Some(time::delay_for(timeout)),
                    None => break,
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn cancel_timeout(&mut self) {
        let _ = self.timer.take();
    }
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + TcpConnection + Unpin,
{
    pub fn split(self) -> (ReadHalf<Connection<S>>, WriteHalf<Connection<S>>) {
        use tokio::io::split;
        split(self)
    }
}

impl<S> AsyncRead for Connection<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.as_mut().project().stream.poll_read(cx, buf) {
            Poll::Ready(r) => {
                self.cancel_timeout();
                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_timeout(cx))?;
                Poll::Pending
            }
        }
    }
}

impl<S> AsyncWrite for Connection<S>
where
    S: AsyncRead + AsyncWrite + TcpConnection + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.as_mut().project().stream.poll_write(cx, buf) {
            Poll::Ready(r) => {
                self.cancel_timeout();

                if !self.written_first_packet {
                    self.written_first_packet = true;

                    if !self.nodelay {
                        // Reset `TCP_NODELAY`
                        if let Err(err) = self.stream.get_ref().set_nodelay(false) {
                            error!("failed to reset TCP_NODELAY on socket, error: {:?}", err);
                        }
                    }
                }

                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_timeout(cx))?;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().project().stream.poll_flush(cx) {
            Poll::Ready(r) => {
                self.cancel_timeout();
                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_timeout(cx))?;
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}
