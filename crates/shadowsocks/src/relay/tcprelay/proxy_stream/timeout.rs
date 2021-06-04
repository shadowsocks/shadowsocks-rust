//! Asynchronous Stream support unified timeout for both Read and Write

use std::{
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{self, Instant, Sleep},
};

#[derive(Debug)]
struct TimeoutState {
    timeout: Option<Duration>,
    cur: Pin<Box<Sleep>>,
    active: bool,
}

impl TimeoutState {
    #[inline]
    fn new() -> TimeoutState {
        TimeoutState {
            timeout: None,
            cur: Box::pin(time::sleep_until(Instant::now())),
            active: false,
        }
    }

    #[inline]
    fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    #[inline]
    fn set_timeout(&mut self, timeout: Option<Duration>) {
        // since this takes &mut self, we can't yet be active
        self.timeout = timeout;
    }

    #[inline]
    fn set_timeout_pinned(mut self: Pin<&mut Self>, timeout: Option<Duration>) {
        self.timeout = timeout;
        self.reset();
    }

    #[inline]
    fn reset(mut self: Pin<&mut Self>) {
        if self.active {
            self.active = false;
            self.cur.as_mut().reset(Instant::now());
        }
    }

    #[inline]
    fn poll_check(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> io::Result<()> {
        let timeout = match self.timeout {
            Some(timeout) => timeout,
            None => return Ok(()),
        };

        if !self.active {
            self.cur.as_mut().reset(Instant::now() + timeout);
            self.active = true;
        }

        match self.cur.as_mut().poll(cx) {
            Poll::Ready(()) => Err(io::Error::from(io::ErrorKind::TimedOut)),
            Poll::Pending => Ok(()),
        }
    }
}

/// A stream that timeouts if both Read and Write are both pending
///
/// IMPLEMENTATION NOTE:
///
/// Because the `TimedStream` internally shared the same `tokio::time::Sleep` state,
/// but it can only remember one `Waker`. Which means that the timeout event can only
/// notify one task, either `poll_read` or `poll_write`.
///
/// If this behavior is not expected, use the `tokio-io-timeout` crate instead.
///
/// If using this stream in a splitted way (ReadHalf and WriteHalf), then you should
/// kill both of them when you read `ErrorKind::TimedOut` from `poll_read` or `poll_write`.
/// In other word, it should work like a bidirection tunnel.
#[pin_project]
pub struct TimedStream<S> {
    #[pin]
    stream: S,
    #[pin]
    timeout_state: TimeoutState,
}

impl<S> TimedStream<S> {
    /// Create a new `TimedStream` with optional timeout
    pub fn new(stream: S, timeout: Option<Duration>) -> TimedStream<S> {
        let mut timeout_state = TimeoutState::new();
        if timeout.is_some() {
            timeout_state.set_timeout(timeout);
        }

        TimedStream { stream, timeout_state }
    }

    /// Get timeout
    #[inline]
    #[allow(dead_code)]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout_state.timeout()
    }

    /// Set timeout exclusively
    #[inline]
    #[allow(dead_code)]
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout_state.set_timeout(timeout)
    }

    /// Set timeout exclusively with Pinned self
    #[inline]
    #[allow(dead_code)]
    pub fn set_timeout_pinned(self: Pin<&mut Self>, timeout: Option<Duration>) {
        self.project().timeout_state.set_timeout_pinned(timeout)
    }

    /// Get immutable reference of internal stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get mutable reference of internal stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the `TimedStream` and return the internal stream
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> AsyncRead for TimedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.project();

        let r = this.stream.poll_read(cx, buf);
        match r {
            Poll::Ready(..) => this.timeout_state.reset(),
            Poll::Pending => this.timeout_state.poll_check(cx)?,
        }
        r
    }
}

impl<S> AsyncWrite for TimedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let this = self.project();

        let r = this.stream.poll_write(cx, buf);
        match r {
            Poll::Ready(..) => this.timeout_state.reset(),
            Poll::Pending => this.timeout_state.poll_check(cx)?,
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.project();

        let r = this.stream.poll_write_vectored(cx, bufs);
        match r {
            Poll::Ready(..) => this.timeout_state.reset(),
            Poll::Pending => this.timeout_state.poll_check(cx)?,
        }
        r
    }
}
