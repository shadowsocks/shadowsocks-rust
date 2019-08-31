//! IO facilities for TCP relay

use std::{
    io::{self, Cursor, Read},
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, BufMut, BytesMut, IntoBuf};
use futures::{
    future::{pending, Pending},
    ready,
};
use tokio::{prelude::*, timer::Timeout};

use super::BUFFER_SIZE;

static DUMMY_BUFFER: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];

/// Reader to read data from ShadowSocks protocol
///
/// This trait requires `BufRead`, because obviously this reader has to contain a buffer inside,
/// which stores the decrypted data.
pub trait DecryptedRead: AsyncRead {
    /// Decrypt buffer size
    fn buffer_size(&self, data: &[u8]) -> usize;

    /// Read data from self and write decrypted data into writer
    fn decrypted_copy_to<'a, W>(&'a mut self, w: &'a mut W, timeout: Option<Duration>) -> DecryptedCopy<'a, Self, W>
    where
        W: AsyncWrite + Unpin,
    {
        DecryptedCopy {
            reader: self,
            writer: w,
            buf: [0u8; BUFFER_SIZE],
            pos: 0,
            cap: 0,
            amount: 0,
            reader_finished: false,
            timeout: timeout,
            timer: None,
        }
    }
}

pub struct DecryptedCopy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    buf: [u8; BUFFER_SIZE],
    pos: usize,
    cap: usize,
    amount: u64,
    reader_finished: bool,
    timeout: Option<Duration>,
    timer: Option<Timeout<Pending<()>>>,
}

impl<R, W> DecryptedCopy<'_, R, W>
where
    R: ?Sized,
    W: ?Sized,
{
    fn clear_timer(&mut self) {
        let _ = self.timer.take();
    }

    fn set_timer(&mut self) {
        if self.timer.is_none() {
            if let Some(dur) = self.timeout {
                self.timer = Some(Timeout::new(pending::<()>(), dur));
            }
        }
    }

    fn poll_timer(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> io::Result<()> {
        self.set_timer();

        if let Some(ref mut t) = self.timer {
            match Pin::new(&mut t).poll(cx) {
                Poll::Ready(Ok(..)) => {
                    // NEVER HAPPENS
                    unreachable!();
                }

                Poll::Ready(Err(err)) => {
                    // Timeout
                    return Err(From::from(err));
                }

                Poll::Pending => {}
            }
        }
        Ok(())
    }
}

impl<R: ?Sized + Unpin, W: ?Sized + Unpin> Unpin for DecryptedCopy<'_, R, W> {}

impl<R, W> Future for DecryptedCopy<'_, R, W>
where
    R: DecryptedRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = &mut *self;

        loop {
            // 1. Send all data remaining in encrypt_buf
            while me.pos < me.cap {
                self.poll_timer(cx)?;
                let n = ready!(Pin::new(&mut me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                self.clear_timer();
                me.pos += n;

                me.amount += n as u64;

                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }

            // 2. If reader is not finished
            if me.reader_finished {
                break;
            }

            // 2.1. Read data from reader
            self.poll_timer(cx)?;
            let n = ready!(Pin::new(&mut me.reader).poll_read(cx, &mut me.buf))?;
            self.clear_timer();

            self.cap = n;
        }

        Poll::Ready(Ok(me.amount))
    }
}

/// Writer that encrypt data and write it as ShadowSocks protocol
///
/// The writer cannot implement `io::Write`, because you cannot ensure that you can write all the data in a batch
/// in non-blocking I/O environment.
pub trait EncryptedWrite: AsyncWrite + Unpin {
    /// Encrypt data into buffer for writing
    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()>;
    /// Encrypt buffer size
    fn buffer_size(&self, data: &[u8]) -> usize;

    /// Encrypt data and write all into writer
    fn encrypted_write_all<'a>(&'a mut self, data: &[u8]) -> EncryptedWriteAll<'a, Self, Cursor<BytesMut>> {
        let buf_size = self.buffer_size(data);
        let mut buf = BytesMut::with_capacity(buf_size);
        self.encrypt(data, &mut buf);
        EncryptedWriteAll {
            writer: self,
            buf: buf.into_buf(),
        }
    }

    /// Read data from reader and write encrypted data into self
    fn encrypted_copy_from<'a, R>(&'a mut self, r: &'a mut R, timeout: Option<Duration>) -> EncryptedCopy<'a, R, Self>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        EncryptedCopy {
            reader: r,
            writer: self,
            encrypt_buf: BytesMut::new(),
            amount: 0,
            encrypt_buf_pos: 0,
            reader_finished: false,
            timeout: timeout,
            timer: None,
        }
    }
}

pub struct EncryptedWriteAll<'a, W: ?Sized, B: Buf> {
    writer: &'a mut W,
    buf: B,
}

impl<W: ?Sized + Unpin, B: Buf> Unpin for EncryptedWriteAll<'_, W, B> {}

impl<W, B> Future for EncryptedWriteAll<'_, W, B>
where
    W: AsyncWrite + Unpin + ?Sized,
    B: Buf,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;

        while me.buf.has_remaining() {
            let n = ready!(Pin::new(&mut me.writer).poll_write(cx, me.buf.bytes()))?;
            me.buf.advance(n);

            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(Ok(()))
    }
}

pub struct EncryptedCopy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    encrypt_buf: BytesMut,
    amount: u64,
    encrypt_buf_pos: usize,
    reader_finished: bool,
    timeout: Option<Duration>,
    timer: Option<Timeout<Pending<()>>>,
}

impl<R, W> EncryptedCopy<'_, R, W>
where
    R: ?Sized,
    W: ?Sized,
{
    fn clear_timer(&mut self) {
        let _ = self.timer.take();
    }

    fn set_timer(&mut self) {
        if self.timer.is_none() {
            if let Some(dur) = self.timeout {
                self.timer = Some(Timeout::new(pending::<()>(), dur));
            }
        }
    }

    fn poll_timer(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> io::Result<()> {
        self.set_timer();

        if let Some(ref mut t) = self.timer {
            match Pin::new(&mut t).poll(cx) {
                Poll::Ready(Ok(..)) => {
                    // NEVER HAPPENS
                    unreachable!();
                }

                Poll::Ready(Err(err)) => {
                    // Timeout
                    return Err(From::from(err));
                }

                Poll::Pending => {}
            }
        }
        Ok(())
    }
}

impl<R: ?Sized + Unpin, W: ?Sized + Unpin> Unpin for EncryptedCopy<'_, R, W> {}

impl<R, W> Future for EncryptedCopy<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: EncryptedWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = &mut *self;

        loop {
            // 1. Send all data remaining in encrypt_buf
            while me.encrypt_buf_pos < me.encrypt_buf.len() {
                self.poll_timer(cx)?;
                let n = ready!(Pin::new(&mut me.writer).poll_write(cx, &me.encrypt_buf[me.encrypt_buf_pos..]))?;
                self.clear_timer();
                me.encrypt_buf_pos += n;

                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }

            // 2. If reader is not finished
            if me.reader_finished {
                break;
            }

            // 2.1. Read data from reader
            let mut buf = [0u8; BUFFER_SIZE];
            self.poll_timer(cx)?;
            let n = ready!(Pin::new(&mut me.reader).poll_read(cx, &mut buf))?;
            self.clear_timer();

            me.amount += n as u64;

            let encrypt_buf_size = me.writer.buffer_size(&buf[..n]);
            me.encrypt_buf.clear();
            me.encrypt_buf.reserve(encrypt_buf_size);
            me.writer.encrypt(&buf[..n], &mut me.encrypt_buf);
            me.encrypt_buf_pos = 0;
        }

        Poll::Ready(Ok(me.amount))
    }
}
