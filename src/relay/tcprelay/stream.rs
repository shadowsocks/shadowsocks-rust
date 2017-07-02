//! Stream protocol implementation

use std::io::{self, Read, BufRead};
use std::cmp;

use crypto::{CipherType, StreamCipher, StreamCipherVariant, CryptoMode, new_stream};
use bytes::{BufMut, BytesMut};
use tokio_io::{AsyncRead, AsyncWrite};

use super::BUFFER_SIZE;
use super::{EncryptedWrite, DecryptedRead};

const DUMMY_BUFFER: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<R>
where
    R: AsyncRead,
{
    reader: R,
    buffer: BytesMut,
    cipher: StreamCipherVariant,
    pos: usize,
    sent_final: bool,
}

impl<R> DecryptedReader<R>
where
    R: AsyncRead,
{
    pub fn new(r: R, t: CipherType, key: &[u8], iv: &[u8]) -> DecryptedReader<R> {
        let cipher = new_stream(t, key, iv, CryptoMode::Decrypt);
        let buffer_size = cipher.buffer_size(&DUMMY_BUFFER);
        DecryptedReader {
            reader: r,
            buffer: BytesMut::with_capacity(buffer_size),
            cipher: cipher,
            pos: 0,
            sent_final: false,
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Gets a mutable reference to the underlying reader.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read directly from or write directly to the
    /// underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Unwraps this `DecryptedReader`, returning the underlying reader.
    ///
    /// The internal buffer is flushed before returning the reader. Any leftover
    /// data in the read buffer is lost.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R> BufRead for DecryptedReader<R>
where
    R: AsyncRead,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.pos >= self.buffer.len() {
            if self.sent_final {
                return Ok(&[]);
            }

            let mut incoming = [0u8; BUFFER_SIZE];
            self.buffer.clear();
            match self.reader.read(&mut incoming) {
                Ok(0) => {
                    // Ensure we have enough space
                    let buffer_len = self.buffer_size(&[]);
                    self.buffer.reserve(buffer_len);

                    // EOF
                    try!(self.cipher.finalize(&mut self.buffer));
                    self.sent_final = true;
                }
                Ok(l) => {
                    let data = &incoming[..l];

                    // Ensure we have enough space
                    let buffer_len = self.buffer_size(data);
                    self.buffer.reserve(buffer_len);

                    try!(self.cipher.update(data, &mut self.buffer));
                }
                Err(err) => {
                    return Err(err);
                }
            }

            self.pos = 0;
        }

        Ok(&self.buffer[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = cmp::min(self.pos + amt, self.buffer.len());
    }
}

impl<R> Read for DecryptedReader<R>
where
    R: AsyncRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let nread = {
            let mut available = try!(self.fill_buf());
            try!(available.read(buf))
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl<R> DecryptedRead for DecryptedReader<R>
where
    R: AsyncRead,
{
    fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.buffer_size(data)
    }
}

impl<R> AsyncRead for DecryptedReader<R>
where
    R: AsyncRead,
{
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<W>
where
    W: AsyncWrite,
{
    writer: W,
    cipher: StreamCipherVariant,
}

impl<W> EncryptedWriter<W>
where
    W: AsyncWrite,
{
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

impl<W> Drop for EncryptedWriter<W>
where
    W: AsyncWrite,
{
    fn drop(&mut self) {
        let mut buf = Vec::new();
        if let Ok(..) = self.cipher_finalize(&mut buf) {
            if !buf.is_empty() {
                let _ = self.write_raw(&buf);
            }
        }
    }
}

impl<W> EncryptedWrite for EncryptedWriter<W>
where
    W: AsyncWrite,
{
    fn write_raw(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writer.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        self.cipher_update(data, buf)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.buffer_size(data)
    }
}
