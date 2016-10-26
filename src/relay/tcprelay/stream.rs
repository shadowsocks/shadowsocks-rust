// The MIT License (MIT)

// Copyright (c) 2015 Y. T. Chung

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#![allow(dead_code)]

use std::io::{self, Read, BufRead, Write};
use std::cmp;

use crypto::{Cipher, CipherVariant};

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<R>
    where R: Read + 'static
{
    reader: R,
    buffer: Vec<u8>,
    cipher: CipherVariant,
    pos: usize,
    sent_final: bool,
}

const BUFFER_SIZE: usize = 2048;

impl<R> DecryptedReader<R>
    where R: Read + 'static
{
    pub fn new(r: R, cipher: CipherVariant) -> DecryptedReader<R> {
        DecryptedReader {
            reader: r,
            buffer: Vec::new(),
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
    where R: Read + 'static
{
    fn fill_buf<'b>(&'b mut self) -> io::Result<&'b [u8]> {
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
    where R: Read + 'static
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

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<W>
    where W: Write + 'static
{
    writer: W,
    cipher: CipherVariant,
    buffer: Vec<u8>,
}

impl<W> EncryptedWriter<W>
    where W: Write + 'static
{
    /// Creates a new EncryptedWriter
    pub fn new(w: W, cipher: CipherVariant) -> EncryptedWriter<W> {
        EncryptedWriter {
            writer: w,
            cipher: cipher,
            buffer: Vec::new(),
        }
    }

    /// Finalize the cipher, which will writes the final block into buffer
    pub fn finalize(&mut self) -> io::Result<()> {
        match self.cipher.finalize(&mut self.buffer) {
            Ok(..) => {
                self.writer
                    .write_all(&self.buffer[..])
                    .and_then(|_| self.writer.flush())
            }
            Err(err) => Err(From::from(err)),
        }
    }

    /// Get reference to the inner writer
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Gets a mutable reference to the underlying writer.
    ///
    /// # Warning
    ///
    /// It is inadvisable to read directly from or write directly to the
    /// underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }
}

impl<W> Write for EncryptedWriter<W>
    where W: Write + 'static
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.cipher.update(buf, &mut self.buffer) {
            Ok(..) => {
                let len = try!(self.writer.write(&self.buffer[..]));
                self.buffer.drain(..len);
                Ok(len)
            }
            Err(err) => Err(From::from(err)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W> Drop for EncryptedWriter<W>
    where W: Write + 'static
{
    fn drop(&mut self) {
        let _ = self.finalize();
    }
}
