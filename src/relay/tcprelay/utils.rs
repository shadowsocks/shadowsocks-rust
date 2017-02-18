//! Utility functions

use std::io::{self, Read, Write};
use std::time::Duration;

use tokio_core::reactor::{Handle, Timeout};
use tokio_core::io::{Copy, copy};

use futures::{Future, Poll, Async};

use super::BUFFER_SIZE;

/// Copies all data from `r` to `w`, abort if timeout reaches
pub fn copy_timeout<R, W>(r: R, w: W, dur: Duration, handle: Handle) -> CopyTimeout<R, W>
    where R: Read,
          W: Write
{
    CopyTimeout::new(r, w, dur, handle)
}

/// Copies all data from `r` to `w`, abort if timeout reaches
pub struct CopyTimeout<R, W>
    where R: Read,
          W: Write
{
    r: R,
    w: W,
    timeout: Duration,
    handle: Handle,
    amt: u64,
    timer: Option<Timeout>,
    buf: [u8; BUFFER_SIZE],
    pos: usize,
    cap: usize,
}

impl<R, W> CopyTimeout<R, W>
    where R: Read,
          W: Write
{
    fn new(r: R, w: W, timeout: Duration, handle: Handle) -> CopyTimeout<R, W> {
        CopyTimeout {
            r: r,
            w: w,
            timeout: timeout,
            handle: handle,
            amt: 0,
            timer: None,
            buf: [0u8; BUFFER_SIZE],
            pos: 0,
            cap: 0,
        }
    }

    fn try_poll_timeout(&mut self) -> io::Result<()> {
        match self.timer.as_mut() {
            None => Ok(()),
            Some(t) => {
                match t.poll() {
                    Err(err) => Err(err),
                    Ok(Async::Ready(..)) => Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
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
        try!(self.try_poll_timeout());

        // Then, unset the previous timeout
        self.clear_timer();

        match self.r.read(&mut self.buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Some(Timeout::new(self.timeout, &self.handle).unwrap());
                }
                Err(e)
            }
        }
    }

    fn write_or_set_timeout(&mut self, beg: usize, end: usize) -> io::Result<usize> {
        // First, return if timeout
        try!(self.try_poll_timeout());

        // Then, unset the previous timeout
        self.clear_timer();

        match self.w.write(&self.buf[beg..end]) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Some(Timeout::new(self.timeout, &self.handle).unwrap());
                }
                Err(e)
            }
        }
    }
}

impl<R, W> Future for CopyTimeout<R, W>
    where R: Read,
          W: Write
{
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if self.pos == self.cap {
                let n = try_nb!(self.read_or_set_timeout());

                if n == 0 {
                    // If we've written al the data and we've seen EOF, flush out the
                    // data and finish the transfer.
                    // done with the entire transfer.
                    try_nb!(self.w.flush());
                    return Ok(self.amt.into());
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
pub fn copy_timeout_opt<R, W>(r: R, w: W, dur: Option<Duration>, handle: Handle) -> CopyTimeoutOpt<R, W>
    where R: Read,
          W: Write
{
    match dur {
        Some(d) => CopyTimeoutOpt::CopyTimeout(copy_timeout(r, w, d, handle)),
        None => CopyTimeoutOpt::Copy(copy(r, w)),
    }
}

/// Copies all data from `R` to `W`
pub enum CopyTimeoutOpt<R: Read, W: Write> {
    Copy(Copy<R, W>),
    CopyTimeout(CopyTimeout<R, W>),
}

impl<R: Read, W: Write> Future for CopyTimeoutOpt<R, W> {
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            CopyTimeoutOpt::CopyTimeout(ref mut c) => c.poll(),
            CopyTimeoutOpt::Copy(ref mut c) => c.poll(),
        }
    }
}