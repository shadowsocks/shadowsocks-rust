//! IO facilities for TCP relay

use std::io::{self, Read, BufRead};
use std::mem;
use std::time::Duration;

use futures::{Future, Poll, Async};

use tokio_core::reactor::Timeout;
use tokio_io::io::{copy, Copy};
use tokio_io::{AsyncRead, AsyncWrite};

use bytes::{BufMut, BytesMut};

use super::BUFFER_SIZE;
use super::utils::{copy_timeout, copy_timeout_opt, CopyTimeout, CopyTimeoutOpt};

use relay::Context;

static DUMMY_BUFFER: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];

/// Reader to read data from ShadowSocks protocol
///
/// This trait requires `BufRead`, because obviously this reader has to contain a buffer inside,
/// which stores the decrypted data.
pub trait DecryptedRead: BufRead + AsyncRead {
    /// Decrypt buffer size
    fn buffer_size(&self, data: &[u8]) -> usize;

    /// Copies all data to `w`
    fn copy<W>(self, w: W) -> Copy<Self, W>
        where Self: Sized,
              W: AsyncWrite
    {
        copy(self, w)
    }

    /// Copies all data to `w`, return `TimedOut` if timeout reaches
    fn copy_timeout<W>(self, w: W, timeout: Duration) -> CopyTimeout<Self, W>
        where Self: Sized,
              W: AsyncWrite
    {
        copy_timeout(self, w, timeout)
    }

    /// The same as `copy_timeout`, but has optional `timeout`
    fn copy_timeout_opt<W>(self, w: W, timeout: Option<Duration>) -> CopyTimeoutOpt<Self, W>
        where Self: Sized,
              W: AsyncWrite
    {
        copy_timeout_opt(self, w, timeout)
    }
}

/// Writer that encrypt data and write it as ShadowSocks protocol
///
/// The writer cannot implement `io::Write`, because you cannot ensure that you can write all the data in a batch
/// in non-blocking I/O environment.
pub trait EncryptedWrite {
    /// Writes raw bytes directly to the writer
    fn write_raw(&mut self, data: &[u8]) -> io::Result<usize>;
    /// Flush the writer
    fn flush(&mut self) -> io::Result<()>;
    /// Encrypt data into buffer for writing
    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()>;
    /// Encrypt buffer size
    fn buffer_size(&self, data: &[u8]) -> usize;

    /// Encrypt data in `buf` and write all to the writer
    fn write_all<B: AsRef<[u8]>>(self, buf: B) -> EncryptedWriteAll<Self, B>
        where Self: Sized
    {
        EncryptedWriteAll::new(self, buf)
    }

    /// Copies all data from `r`
    fn copy<R: Read>(self, r: R) -> EncryptedCopy<R, Self>
        where Self: Sized
    {
        EncryptedCopy::new(r, self)
    }

    /// Copies all data from `r` with timeout
    fn copy_timeout<R: Read>(self, r: R, timeout: Duration) -> EncryptedCopyTimeout<R, Self>
        where Self: Sized
    {
        EncryptedCopyTimeout::new(r, self, timeout)
    }

    /// Copies all data from `r` with optional timeout
    fn copy_timeout_opt<R: Read>(self, r: R, timeout: Option<Duration>) -> EncryptedCopyOpt<R, Self>
        where Self: Sized
    {
        match timeout {
            Some(t) => EncryptedCopyOpt::CopyTimeout(self.copy_timeout(r, t)),
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
        enc_buf: BytesMut,
        encrypted: bool,
    },
    Empty,
}

impl<W, B> EncryptedWriteAll<W, B>
    where W: EncryptedWrite,
          B: AsRef<[u8]>
{
    fn new(w: W, buf: B) -> EncryptedWriteAll<W, B> {
        let buffer_size = w.buffer_size(&DUMMY_BUFFER);
        EncryptedWriteAll::Writing {
            writer: w,
            buf: buf,
            pos: 0,
            enc_buf: BytesMut::with_capacity(buffer_size),
            encrypted: false,
        }
    }
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
            EncryptedWriteAll::Writing {
                ref mut writer,
                ref buf,
                ref mut pos,
                ref mut enc_buf,
                ref mut encrypted,
            } => {
                if !*encrypted {
                    *encrypted = true;

                    // Ensure buffer has enough space
                    let buffer_len = writer.buffer_size(buf.as_ref());
                    enc_buf.reserve(buffer_len);

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
pub struct EncryptedCopy<R, W>
    where R: Read,
          W: EncryptedWrite
{
    reader: Option<R>,
    writer: Option<W>,
    read_done: bool,
    amt: u64,
    pos: usize,
    cap: usize,
    buf: BytesMut,
}

impl<R, W> EncryptedCopy<R, W>
    where R: Read,
          W: EncryptedWrite
{
    fn new(r: R, w: W) -> EncryptedCopy<R, W> {
        let buffer_size = w.buffer_size(&DUMMY_BUFFER);
        EncryptedCopy {
            reader: Some(r),
            writer: Some(w),
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            buf: BytesMut::with_capacity(buffer_size),
        }
    }
}

impl<R, W> Future for EncryptedCopy<R, W>
    where R: Read,
          W: EncryptedWrite
{
    type Item = (u64, R, W);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut local_buf = [0u8; BUFFER_SIZE];
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let n = try_nb!(self.reader.as_mut().unwrap().read(&mut local_buf[..]));
                self.buf.clear();
                if n == 0 {
                    self.read_done = true;
                } else {
                    let data = &local_buf[..n];
                    // Ensure we have enough space
                    let buffer_len = self.writer.as_mut().unwrap().buffer_size(data);
                    self.buf.reserve(buffer_len);

                    self.writer.as_mut().unwrap().encrypt(data, &mut self.buf)?;
                }
                self.pos = 0;
                self.cap = self.buf.len();
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let i = try_nb!(self.writer
                                    .as_mut()
                                    .unwrap()
                                    .write_raw(&self.buf[self.pos..self.cap]));
                self.pos += i;
                self.amt += i as u64;
            }

            // If we've written al the data and we've seen EOF, flush out the
            // data and finish the transfer.
            // done with the entire transfer.
            if self.pos == self.cap && self.read_done {
                try_nb!(self.writer.as_mut().unwrap().flush());
                return Ok((self.amt, self.reader.take().unwrap(), self.writer.take().unwrap()).into());
            }
        }
    }
}

/// Encrypted copy
pub struct EncryptedCopyTimeout<R, W>
    where R: Read,
          W: EncryptedWrite
{
    reader: Option<R>,
    writer: Option<W>,
    read_done: bool,
    amt: u64,
    pos: usize,
    cap: usize,
    timeout: Duration,
    timer: Option<Timeout>,
    read_buf: [u8; BUFFER_SIZE],
    write_buf: BytesMut,
}

impl<R, W> EncryptedCopyTimeout<R, W>
    where R: Read,
          W: EncryptedWrite
{
    fn new(r: R, w: W, dur: Duration) -> EncryptedCopyTimeout<R, W> {
        let buffer_size = w.buffer_size(&DUMMY_BUFFER);
        EncryptedCopyTimeout {
            reader: Some(r),
            writer: Some(w),
            read_done: false,
            amt: 0,
            pos: 0,
            cap: 0,
            timeout: dur,
            timer: None,
            read_buf: [0u8; BUFFER_SIZE],
            write_buf: BytesMut::with_capacity(buffer_size),
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
        self.try_poll_timeout()?;

        // Then, unset the previous timeout
        self.clear_timer();

        self.write_buf.clear();
        match self.reader.as_mut().unwrap().read(&mut self.read_buf) {
            Ok(0) => {
                self.cap = 0;
                self.pos = 0;
                Ok(0)
            }
            Ok(n) => {
                let data = &self.read_buf[..n];
                // Ensoure we have enough space
                let buffer_len = self.writer.as_mut().unwrap().buffer_size(data);
                self.write_buf.reserve(buffer_len);

                self.writer
                    .as_mut()
                    .unwrap()
                    .encrypt(data, &mut self.write_buf)?;
                self.cap = self.write_buf.len();
                self.pos = 0;
                Ok(n)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    Context::with(|ctx| self.timer = Some(Timeout::new(self.timeout, ctx.handle()).unwrap()));
                }
                Err(e)
            }
        }
    }

    fn write_or_set_timeout(&mut self) -> io::Result<usize> {
        // First, return if timeout
        self.try_poll_timeout()?;

        // Then, unset the previous timeout
        self.clear_timer();

        match self.writer
                  .as_mut()
                  .unwrap()
                  .write_raw(&self.write_buf[self.pos..self.cap]) {
            Ok(n) => {
                self.pos += n;
                Ok(n)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Context::with(|ctx| Some(Timeout::new(self.timeout, ctx.handle()).unwrap()));
                }
                Err(e)
            }
        }
    }
}

impl<R, W> Future for EncryptedCopyTimeout<R, W>
    where R: Read,
          W: EncryptedWrite
{
    type Item = (u64, R, W);
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
                try_nb!(self.writer.as_mut().unwrap().flush());
                return Ok((self.amt, self.reader.take().unwrap(), self.writer.take().unwrap()).into());
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
    type Item = (u64, R, W);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            EncryptedCopyOpt::Copy(ref mut c) => c.poll(),
            EncryptedCopyOpt::CopyTimeout(ref mut c) => c.poll(),
        }
    }
}
