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
use std::time::Duration;

use crypto::{Cipher, CipherVariant};

use futures::{Future, Poll, Async};

use tokio_core::reactor::{Handle, Timeout};
use tokio_core::io::copy;

use super::{BUFFER_SIZE, BoxIoFuture, boxed_future};

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader<R>
    where R: Read
{
    reader: R,
    buffer: Vec<u8>,
    cipher: CipherVariant,
    pos: usize,
    sent_final: bool,
}

impl<R> DecryptedReader<R>
    where R: Read
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
    where R: Read
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

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter<W>
    where W: Write
{
    writer: W,
    cipher: CipherVariant,
    buf: Vec<u8>,
    finalized: bool,
}

impl<W> EncryptedWriter<W>
    where W: Write
{
    /// Creates a new EncryptedWriter
    pub fn new(w: W, cipher: CipherVariant) -> EncryptedWriter<W> {
        EncryptedWriter {
            writer: w,
            cipher: cipher,
            buf: Vec::new(),
            finalized: false,
        }
    }

    fn cipher_finalize(&mut self) -> io::Result<()> {
        if self.finalized {
            return Ok(());
        }

        self.cipher
            .finalize(&mut self.buf)
            .and_then(|_| {
                self.finalized = true;
                Ok(())
            })
            .map_err(From::from)
    }

    fn flush_buf(&mut self) -> io::Result<usize> {
        let mut written = 0;
        let expected_len = self.buf.len();
        let mut ret = Ok(());
        while written < expected_len {
            match self.writer.write(&self.buf[written..]) {
                Ok(0) => {
                    ret = Err(io::Error::new(io::ErrorKind::WriteZero,
                                             "failed to write the buffered data"));
                    break;
                }
                Ok(n) => written += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            }
        }

        if written > 0 {
            self.buf.drain(..written);
        }

        ret.map(|_| written)
    }

    fn fill_buf(&mut self, data: &[u8]) -> io::Result<()> {
        assert!(!self.finalized, "Called fill_buf after finalized!");

        self.cipher.update(data, &mut self.buf).map_err(From::from)
    }
}

impl<W> EncryptedWriter<W>
    where W: Write + 'static
{
    /// Copy all data from reader with timeout
    pub fn copy_from_encrypted_timeout<R>(self, r: R, timeout: Option<Duration>, handle: Handle) -> BoxIoFuture<u64>
        where R: Read + 'static
    {
        match timeout {
            Some(timeout) => boxed_future(EncryptedCopyTimeout::new(r, self, timeout, handle)),
            None => boxed_future(copy(r, self)),
        }
    }
}

impl<W> Write for EncryptedWriter<W>
    where W: Write
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.buf.is_empty() {
            self.flush_buf()?;
        }

        self.fill_buf(buf)?;
        match self.flush_buf() {
            Ok(..) => {}
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf().and_then(|_| self.writer.flush())
    }
}

impl<W> Drop for EncryptedWriter<W>
    where W: Write
{
    fn drop(&mut self) {
        if let Ok(..) = self.cipher_finalize() {
            // I don't care if it is failed to write
            let _ = self.flush_buf();
        }
    }
}

/// Encrypted copy
pub struct EncryptedCopyTimeout<R: Read, W: Write> {
    reader: R,
    writer: EncryptedWriter<W>,
    read_done: bool,
    amt: u64,
    pos: usize,
    cap: usize,
    timeout: Duration,
    handle: Handle,
    timer: Option<Timeout>,
    read_buf: [u8; BUFFER_SIZE],
}

impl<R: Read, W: Write> EncryptedCopyTimeout<R, W> {
    fn new(r: R, w: EncryptedWriter<W>, dur: Duration, handle: Handle) -> EncryptedCopyTimeout<R, W> {
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

        match self.reader.read(&mut self.read_buf) {
            Ok(n) => {
                self.cap = n;
                self.pos = 0;
                Ok(n)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Some(Timeout::new(self.timeout, &self.handle).unwrap());
                }
                return Err(e);
            }
        }
    }

    fn write_or_set_timeout(&mut self) -> io::Result<usize> {
        // First, return if timeout
        try!(self.try_poll_timeout());

        // Then, unset the previous timeout
        self.clear_timer();

        match self.writer.write(&self.read_buf[self.pos..self.cap]) {
            Ok(n) => {
                self.pos += n;
                Ok(n)
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.timer = Some(Timeout::new(self.timeout, &self.handle).unwrap());
                }
                return Err(e);
            }
        }
    }
}

impl<R: Read, W: Write> Future for EncryptedCopyTimeout<R, W> {
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