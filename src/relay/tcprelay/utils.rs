//! Utility functions

use std::io;
use std::time::Duration;

use tokio_core::reactor::Timeout;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{copy, Copy};

use futures::{Async, Future, Poll};

use relay::Context;

use super::BUFFER_SIZE;

/// Copies all data from `r` to `w`, abort if timeout reaches
pub fn copy_timeout<R, W>(r: R, w: W, dur: Duration) -> CopyTimeout<R, W>
    where R: AsyncRead,
          W: AsyncWrite
{
    CopyTimeout::new(r, w, dur)
}

/// Copies all data from `r` to `w`, abort if timeout reaches
pub struct CopyTimeout<R, W>
    where R: AsyncRead,
          W: AsyncWrite
{
    r: Option<R>,
    w: Option<W>,
    timeout: Duration,
    amt: u64,
    timer: Option<Timeout>,
    buf: [u8; BUFFER_SIZE],
    pos: usize,
    cap: usize,
}

impl<R, W> CopyTimeout<R, W>
    where R: AsyncRead,
          W: AsyncWrite
{
    fn new(r: R, w: W, timeout: Duration) -> CopyTimeout<R, W> {
        CopyTimeout { r: Some(r),
                      w: Some(w),
                      timeout: timeout,
                      amt: 0,
                      timer: None,
                      buf: [0u8; BUFFER_SIZE],
                      pos: 0,
                      cap: 0, }
    }

    fn try_poll_timeout(&mut self) -> io::Result<()> {
        match self.timer.as_mut() {
            None => Ok(()),
            Some(t) => {
                match t.poll() {
                    Err(err) => Err(err),
                    Ok(Async::Ready(..)) => Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out")),
                    Ok(Async::NotReady) => Ok(()),
                }
            }
        }
    }

    fn clear_timer(&mut self) {
        let _ = self.timer.take();
    }

    fn read_or_set_timeout(&mut self) -> io::Result<usize> {
        // First, return if timeout
        self.try_poll_timeout()?;

        // Then, unset the previous timeout
        self.clear_timer();

        match self.r.as_mut().unwrap().read(&mut self.buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Context::with(|ctx| Some(Timeout::new(self.timeout, ctx.handle()).unwrap()));
                }
                Err(e)
            }
        }
    }

    fn write_or_set_timeout(&mut self, beg: usize, end: usize) -> io::Result<usize> {
        // First, return if timeout
        self.try_poll_timeout()?;

        // Then, unset the previous timeout
        self.clear_timer();

        match self.w.as_mut().unwrap().write(&self.buf[beg..end]) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Context::with(|ctx| Some(Timeout::new(self.timeout, ctx.handle()).unwrap()));
                }
                Err(e)
            }
        }
    }
}

impl<R, W> Future for CopyTimeout<R, W>
    where R: AsyncRead,
          W: AsyncWrite
{
    type Item = (u64, R, W);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if self.pos == self.cap {
                let n = try_nb!(self.read_or_set_timeout());

                if n == 0 {
                    // If we've written all the data and we've seen EOF, flush out the
                    // data and finish the transfer.
                    // done with the entire transfer.
                    try_nb!(self.w.as_mut().unwrap().flush());
                    return Ok((self.amt, self.r.take().unwrap(), self.w.take().unwrap()).into());
                }

                self.pos = 0;
                self.cap = n;

                // Clear it before write
                self.clear_timer();
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let (pos, cap) = (self.pos, self.cap);
                let i = try_nb!(self.write_or_set_timeout(pos, cap));
                self.pos += i;
                self.amt += i as u64;
            }

            // Clear it before read
            self.clear_timer();
        }
    }
}

/// Copies all data from `r` to `w` with optional timeout param
pub fn copy_timeout_opt<R, W>(r: R, w: W, dur: Option<Duration>) -> CopyTimeoutOpt<R, W>
    where R: AsyncRead,
          W: AsyncWrite
{
    match dur {
        Some(d) => CopyTimeoutOpt::CopyTimeout(copy_timeout(r, w, d)),
        None => CopyTimeoutOpt::Copy(copy(r, w)),
    }
}

/// Copies all data from `R` to `W`
pub enum CopyTimeoutOpt<R: AsyncRead, W: AsyncWrite> {
    Copy(Copy<R, W>),
    CopyTimeout(CopyTimeout<R, W>),
}

impl<R: AsyncRead, W: AsyncWrite> Future for CopyTimeoutOpt<R, W> {
    type Item = (u64, R, W);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            CopyTimeoutOpt::CopyTimeout(ref mut c) => c.poll(),
            CopyTimeoutOpt::Copy(ref mut c) => c.poll(),
        }
    }
}
