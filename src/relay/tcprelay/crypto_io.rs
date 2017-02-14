//! IO facilities for TCP relay

use std::io::{self, Read, BufRead};
use std::mem;
use std::time::Duration;

use futures::{Future, Poll, Async};

use tokio_core::reactor::{Handle, Timeout};

use super::BUFFER_SIZE;

pub trait DecryptedRead: BufRead {}

pub trait EncryptedWrite: Sized {
    /// Writes raw bytes directly to the writer directly
    fn write_raw(&mut self, data: &[u8]) -> io::Result<usize>;
    /// Flush the writer
    fn flush(&mut self) -> io::Result<()>;
    /// Encrypt data into buffer for writing
    fn encrypt(&mut self, data: &[u8], buf: &mut Vec<u8>) -> io::Result<()>;

    /// Encrypt data in `buf` and write all to the writer
    fn write_all<B: AsRef<[u8]>>(self, buf: B) -> EncryptedWriteAll<Self, B> {
        EncryptedWriteAll::Writing {
            writer: self,
            buf: buf,
            pos: 0,
            enc_buf: Vec::new(),
            encrypted: false,
        }
    }

    /// Copies all data from `r`
    fn copy<R: Read>(self, r: R) -> EncryptedCopy<R, Self> {
        EncryptedCopy {
            reader: r,
            writer: self,
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: Vec::new(),
        }
    }

    /// Copies all data from `r` with timeout
    fn copy_timeout<R: Read>(self, r: R, timeout: Duration, handle: Handle) -> EncryptedCopyTimeout<R, Self> {
        EncryptedCopyTimeout::new(r, self, timeout, handle)
    }

    /// Copies all data from `r` with optional timeout
    fn copy_timeout_opt<R: Read>(self, r: R, timeout: Option<Duration>, handle: Handle) -> EncryptedCopyOpt<R, Self> {
        match timeout {
            Some(t) => EncryptedCopyOpt::CopyTimeout(self.copy_timeout(r, t, handle)),
            None => EncryptedCopyOpt::Copy(self.copy(r)),
        }
    }
}

/// Write all data encrypted
pub enum EncryptedWriteAll<W, B>
    where W: EncryptedWrite,
          B: AsRef<[u8]>
{
    Writing {
        writer: W,
        buf: B,
        pos: usize,
        enc_buf: Vec<u8>,
        encrypted: bool,
    },
    Empty,
}

impl<W, B> Future for EncryptedWriteAll<W, B>
    where W: EncryptedWrite,
          B: AsRef<[u8]>
{
    type Item = (W, B);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            EncryptedWriteAll::Empty => panic!("poll after EncryptedWriteAll finished"),
            EncryptedWriteAll::Writing { ref mut writer, ref buf, ref mut pos, ref mut enc_buf, ref mut encrypted } => {
                if !*encrypted {
                    *encrypted = true;
                    writer.encrypt(buf.as_ref(), enc_buf)?;
                }

                while *pos < enc_buf.len() {
                    let n = try_nb!(writer.write_raw(&enc_buf[*pos..]));
                    *pos += n;
                    if n == 0 {
                        let err = io::Error::new(io::ErrorKind::Other, "zero-length write");
                        return Err(err);
                    }
                }
            }
        }

        match mem::replace(self, EncryptedWriteAll::Empty) {
            EncryptedWriteAll::Writing { writer, buf, .. } => Ok((writer, buf).into()),
            EncryptedWriteAll::Empty => unreachable!(),
        }
    }
}

/// Encrypted copy
pub struct EncryptedCopy<R: Read, W: EncryptedWrite> {
    reader: R,
    writer: W,
    read_done: bool,
    amt: u64,
    pos: usize,
    cap: usize,
    buf: Vec<u8>,
}

impl<R: Read, W: EncryptedWrite> Future for EncryptedCopy<R, W> {
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut local_buf = [0u8; BUFFER_SIZE];
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(self.reader.read(&mut local_buf[..]));
                self.buf.clear();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.writer.encrypt(&local_buf[..n], &mut self.buf)?;
                }
                self.pos = 0;
                self.cap = self.buf.len();
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let i = try_nb!(self.writer.write_raw(&self.buf[self.pos..self.cap]));
                self.pos += i;
                self.amt += i as u64;
            }

            // If we've written al the data and we've seen EOF, flush out the
            // data and finish the transfer.
            // done with the entire transfer.
            if self.pos == self.cap && self.read_done {
                try_nb!(self.writer.flush());
                return Ok(self.amt.into());
            }
        }
    }
}

/// Encrypted copy
pub struct EncryptedCopyTimeout<R: Read, W: EncryptedWrite> {
    reader: R,
    writer: W,
    read_done: bool,
    amt: u64,
    pos: usize,
    cap: usize,
    timeout: Duration,
    handle: Handle,
    timer: Option<Timeout>,
    read_buf: [u8; BUFFER_SIZE],
    write_buf: Vec<u8>,
}

impl<R: Read, W: EncryptedWrite> EncryptedCopyTimeout<R, W> {
    fn new(r: R, w: W, dur: Duration, handle: Handle) -> EncryptedCopyTimeout<R, W> {
        EncryptedCopyTimeout {
            reader: r,
            writer: w,
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            timeout: dur,
            handle: handle,
            timer: None,
            read_buf: [0u8; BUFFER_SIZE],
            write_buf: Vec::new(),
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

        self.write_buf.clear();
        match self.reader.read(&mut self.read_buf) {
            Ok(0) => {
                self.cap = 0;
                self.pos = 0;
                Ok(0)
            }
            Ok(n) => {
                self.writer.encrypt(&self.read_buf[..n], &mut self.write_buf)?;
                self.cap = self.write_buf.len();
                self.pos = 0;
                Ok(n)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Some(Timeout::new(self.timeout, &self.handle).unwrap());
                }
                Err(e)
            }
        }
    }

    fn write_or_set_timeout(&mut self) -> io::Result<usize> {
        // First, return if timeout
        try!(self.try_poll_timeout());

        // Then, unset the previous timeout
        self.clear_timer();

        match self.writer.write_raw(&self.write_buf[self.pos..self.cap]) {
            Ok(n) => {
                self.pos += n;
                Ok(n)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Some(Timeout::new(self.timeout, &self.handle).unwrap());
                }
                Err(e)
            }
        }
    }
}

impl<R: Read, W: EncryptedWrite> Future for EncryptedCopyTimeout<R, W> {
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {

        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(self.read_or_set_timeout());
                if n == 0 {
                    self.read_done = true;
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let i = try_nb!(self.write_or_set_timeout());
                if i == 0 {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "early eof");
                    return Err(err);
                }
                self.amt += i as u64;
            }

            // If we've written al the data and we've seen EOF, flush out the
            // data and finish the transfer.
            // done with the entire transfer.
            if self.pos == self.cap && self.read_done {
                try_nb!(self.writer.flush());
                return Ok(self.amt.into());
            }
        }
    }
}

/// Work for both timeout or no timeout
pub enum EncryptedCopyOpt<R, W>
    where R: Read,
          W: EncryptedWrite
{
    Copy(EncryptedCopy<R, W>),
    CopyTimeout(EncryptedCopyTimeout<R, W>),
}

impl<R, W> Future for EncryptedCopyOpt<R, W>
    where R: Read,
          W: EncryptedWrite
{
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            EncryptedCopyOpt::Copy(ref mut c) => c.poll(),
            EncryptedCopyOpt::CopyTimeout(ref mut c) => c.poll(),
        }
    }
}