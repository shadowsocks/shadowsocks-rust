//! Stream protocol implementation
use std::{
    io,
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto::v1::{Cipher, CipherKind};

// use super::BUFFER_SIZE;

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    cipher: Cipher,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8], iv: &[u8]) -> DecryptedReader {
        let cipher = Cipher::new(method, key, iv);
        DecryptedReader { cipher }
    }

    /// Attempt to read decrypted data from reader
    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let filled = dst.filled().len();
        ready!(Pin::new(r).poll_read(ctx, dst))?;

        // Decrypt inplace
        let m = &mut dst.filled_mut()[filled..];
        if !m.is_empty() {
            assert_eq!(self.cipher.decrypt_packet(m), true);
        }

        Poll::Ready(Ok(()))
    }
}

enum EncryptWriteStep {
    Nothing,
    Writing,
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher: Cipher,
    steps: EncryptWriteStep,
    buf: BytesMut,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(method: CipherKind, key: &[u8], iv: &[u8]) -> EncryptedWriter {
        // iv should be sent with the first packet
        let mut buf = BytesMut::with_capacity(iv.len());
        buf.put(iv);

        EncryptedWriter {
            cipher: Cipher::new(method, key, &iv),
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
                    let mut payload = data.to_vec();
                    self.cipher.encrypt_packet(&mut payload);
                    self.buf.put_slice(&payload);

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
}
