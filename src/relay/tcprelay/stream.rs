//! Stream protocol implementation

use std::io::{self, Read, BufRead, Write};
use std::cmp;

use crypto::{CipherType, StreamCipher, StreamCipherVariant, CryptoMode, new_stream};

use super::BUFFER_SIZE;
use super::{EncryptedWrite, DecryptedRead};

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<R>
    where R: Read
{
    reader: R,
    buffer: Vec<u8>,
    cipher: StreamCipherVariant,
    pos: usize,
    sent_final: bool,
}

impl<R> DecryptedReader<R>
    where R: Read
{
    pub fn new(r: R, t: CipherType, key: &[u8], iv: &[u8]) -> DecryptedReader<R> {
        DecryptedReader {
            reader: r,
            buffer: Vec::new(),
            cipher: new_stream(t, key, iv, CryptoMode::Decrypt),
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
    where R: Read
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
                    // EOF
                    try!(self.cipher
                        .finalize(&mut self.buffer));
                    self.sent_final = true;
                }
                Ok(l) => {
                    try!(self.cipher
                        .update(&incoming[..l], &mut self.buffer));
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
    where R: Read
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

impl<R> DecryptedRead for DecryptedReader<R> where R: Read {}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<W>
    where W: Write
{
    writer: W,
    cipher: StreamCipherVariant,
}

impl<W> EncryptedWriter<W>
    where W: Write
{
    /// Creates a new EncryptedWriter
    pub fn new(w: W, t: CipherType, key: &[u8], iv: &[u8]) -> EncryptedWriter<W> {
        EncryptedWriter {
            writer: w,
            cipher: new_stream(t, key, iv, CryptoMode::Encrypt),
        }
    }

    fn cipher_update(&mut self, data: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        self.cipher.update(data, buf).map_err(From::from)
    }

    fn cipher_finalize(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        self.cipher.finalize(buf).map_err(From::from)
    }
}

impl<W> Drop for EncryptedWriter<W>
    where W: Write
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
    where W: Write
{
    fn write_raw(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writer.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn encrypt(&mut self, data: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
        self.cipher_update(data, buf)
    }
}