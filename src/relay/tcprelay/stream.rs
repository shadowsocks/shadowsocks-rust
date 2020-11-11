//! Stream protocol implementation

use std::{
    cmp,
    io,
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
};

use crate::crypto::{new_stream, BoxStreamCipher, CipherType, CryptoMode};
use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::BUFFER_SIZE;

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    buffer: BytesMut,
    cipher: BoxStreamCipher,
    pos: usize,
    got_final: bool,
    incoming_buffer: Box<[u8]>,
}

impl DecryptedReader {
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> DecryptedReader {
        let cipher = new_stream(t, key, iv, CryptoMode::Decrypt);
        DecryptedReader {
            buffer: BytesMut::new(),
            cipher,
            pos: 0,
            got_final: false,
            incoming_buffer: vec![0u8; BUFFER_SIZE].into_boxed_slice(),
        }
    }

    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        while self.pos >= self.buffer.len() {
            if self.got_final {
                return Poll::Ready(Ok(()));
            }

            let mut buf = ReadBuf::new(&mut self.incoming_buffer);
            ready!(Pin::new(&mut *r).poll_read(ctx, &mut buf))?;
            let data = buf.filled();

            // Reset pointers
            // So the outer loop will break if data.len() != 0
            self.buffer.clear();
            self.pos = 0;

            if data.len() == 0 {
                // Finialize block
                self.buffer.reserve(self.cipher.buffer_size(&[]));
                self.cipher.finalize(&mut self.buffer)?;
                self.got_final = true;
            } else {
                // Ensure we have enough space
                let buffer_len = self.cipher.buffer_size(data);
                self.buffer.reserve(buffer_len);
                self.cipher.update(data, &mut self.buffer)?;
            }
        }

        let remaining_len = self.buffer.len() - self.pos;
        let n = cmp::min(dst.remaining(), remaining_len);
        dst.put_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }
}

enum EncryptWriteStep {
    Nothing,
    Writing,
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher: BoxStreamCipher,
    steps: EncryptWriteStep,
    buf: BytesMut,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> EncryptedWriter {
        // iv should be sent with the first packet
        let mut buf = BytesMut::with_capacity(iv.len());
        buf.put(iv);

        EncryptedWriter {
            cipher: new_stream(t, key, &iv, CryptoMode::Encrypt),
            steps: EncryptWriteStep::Nothing,
            buf,
        }
    }

    pub fn poll_write_encrypted<W>(&mut self, ctx: &mut Context<'_>, w: &mut W, data: &[u8]) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        ready!(self.poll_write_all_encrypted(ctx, w, data))?;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_all_encrypted<W>(&mut self, ctx: &mut Context<'_>, w: &mut W, data: &[u8]) -> Poll<io::Result<()>>
    where
        W: AsyncWrite + Unpin,
    {
        // FIXME: How about finalize?

        loop {
            match self.steps {
                EncryptWriteStep::Nothing => {
                    self.buf.reserve(self.buffer_size(data));
                    self.cipher.update(data, &mut self.buf)?;
                    self.steps = EncryptWriteStep::Writing;
                }
                EncryptWriteStep::Writing => {
                    while self.buf.has_remaining() {
                        let n = ready!(Pin::new(&mut *w).poll_write(ctx, self.buf.bytes()))?;
                        self.buf.advance(n);
                        if n == 0 {
                            use std::io::ErrorKind;
                            return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                        }
                    }

                    self.steps = EncryptWriteStep::Nothing;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.buffer_size(data)
    }
}
