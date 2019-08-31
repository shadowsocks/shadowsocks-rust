//! Stream protocol implementation

use std::{
    cmp,
    io::{self, Read},
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
};

use crate::crypto::{new_stream, BoxStreamCipher, CipherType, CryptoMode};
use bytes::{BufMut, BytesMut};
use tokio::prelude::*;

use super::{DecryptedRead, EncryptedWrite, BUFFER_SIZE};

const DUMMY_BUFFER: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<R> {
    reader: R,
    buffer: BytesMut,
    cipher: BoxStreamCipher,
    pos: usize,
    sent_final: bool,
}

impl<R> DecryptedReader<R> {
    pub fn new(r: R, t: CipherType, key: &[u8], iv: &[u8]) -> DecryptedReader<R> {
        let cipher = new_stream(t, key, iv, CryptoMode::Decrypt);
        let buffer_size = cipher.buffer_size(&DUMMY_BUFFER);
        DecryptedReader {
            reader: r,
            buffer: BytesMut::with_capacity(buffer_size),
            cipher,
            pos: 0,
            sent_final: false,
        }
    }
}

// Forward Unpin
impl<A: Unpin> Unpin for DecryptedReader<A> {}

impl<R> AsyncBufRead for DecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        while self.pos >= self.buffer.len() {
            if self.sent_final {
                return Poll::Ready(Ok(&[]));
            }

            let mut incoming = [0u8; BUFFER_SIZE];
            self.buffer.clear();
            let l = match Pin::new(&mut self.reader).poll_read(cx, &mut incoming)? {
                Poll::Ready(t) => t,
                Poll::Pending => return Poll::Pending,
            };
            if l == 0 {
                // Ensure we have enough space
                let buffer_len = self.buffer_size(&[]);
                self.buffer.reserve(buffer_len);

                // EOF
                self.cipher.finalize(&mut self.buffer)?;
                self.sent_final = true;
            } else {
                let data = &incoming[..l];

                // Ensure we have enough space
                let buffer_len = self.buffer_size(data);
                self.buffer.reserve(buffer_len);

                self.cipher.update(data, &mut self.buffer)?;
            }

            self.pos = 0;
        }

        Poll::Ready(Ok(&self.buffer[self.pos..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.buffer.len());
    }
}

impl<R> AsyncRead for DecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let nread = {
            let mut available = match self.poll_fill_buf(cx)? {
                Poll::Ready(a) => a,
                Poll::Pending => return Poll::Pending,
            };

            let len = available.len().min(buf.len());
            buf.copy_from_slice(&available[..len]);
            len
        };
        self.consume(nread);
        Poll::Ready(Ok(nread))
    }
}

impl<R> DecryptedRead for DecryptedReader<R>
where
    R: AsyncRead + Unpin,
{
    fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.buffer_size(data)
    }
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<W> {
    writer: W,
    cipher: BoxStreamCipher,
}

impl<W> EncryptedWriter<W> {
    /// Creates a new EncryptedWriter
    pub fn new(w: W, t: CipherType, key: &[u8], iv: &[u8]) -> EncryptedWriter<W> {
        EncryptedWriter {
            writer: w,
            cipher: new_stream(t, key, iv, CryptoMode::Encrypt),
        }
    }

    fn cipher_update<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        self.cipher.update(data, buf).map_err(From::from)
    }

    fn cipher_finalize<B: BufMut>(&mut self, buf: &mut B) -> io::Result<()> {
        self.cipher.finalize(buf).map_err(From::from)
    }
}

// Forward Unpin
impl<A: Unpin> Unpin for EncryptedWriter<A> {}

impl<W> EncryptedWrite for EncryptedWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        self.cipher_update(data, buf)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.buffer_size(data)
    }
}

impl<W> AsyncWrite for EncryptedWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
