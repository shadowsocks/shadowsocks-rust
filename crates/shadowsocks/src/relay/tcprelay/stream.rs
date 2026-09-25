//! Stream protocol implementation
use std::{
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
    slice,
    task::{self, Poll},
};

use byte_string::ByteStr;
use bytes::{BufMut, Bytes, BytesMut};
use futures::ready;
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    context::Context,
    crypto::{CipherKind, v1::Cipher},
};

/// Stream protocol error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("decrypt failed")]
    DecryptError,
}

/// Stream protocol result
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<ProtocolError> for io::Error {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::IoError(err) => err,
            _ => Self::other(e),
        }
    }
}

enum DecryptReadState {
    WaitIv { key: Bytes },
    Read,
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    state: DecryptReadState,
    cipher: Option<Cipher>,
    buffer: BytesMut,
    method: CipherKind,
    iv: Option<Bytes>,
    has_handshaked: bool,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8]) -> Self {
        if method.iv_len() > 0 {
            Self {
                state: DecryptReadState::WaitIv {
                    key: Bytes::copy_from_slice(key),
                },
                cipher: None,
                buffer: BytesMut::with_capacity(method.iv_len()),
                method,
                iv: None,
                has_handshaked: false,
            }
        } else {
            Self {
                state: DecryptReadState::Read,
                cipher: Some(Cipher::new(method, key, &[])),
                buffer: BytesMut::new(),
                method,
                iv: Some(Bytes::new()),
                has_handshaked: false,
            }
        }
    }

    pub fn iv(&self) -> Option<&[u8]> {
        self.iv.as_deref()
    }

    /// Attempt to read decrypted data from reader
    pub fn poll_read_decrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.state {
                DecryptReadState::WaitIv { ref key } => {
                    let key = unsafe { &*(key.as_ref() as *const _) };
                    ready!(self.poll_read_iv(cx, context, stream, key))?;

                    self.buffer.clear();
                    self.buffer.truncate(0);
                    self.state = DecryptReadState::Read;
                    self.has_handshaked = true;
                }
                DecryptReadState::Read => {
                    let before_n = buf.filled().len();
                    ready!(Pin::new(stream).poll_read(cx, buf))?;
                    let after_n = buf.filled().len();
                    if before_n == after_n {
                        return Ok(()).into();
                    }

                    let m = &mut buf.filled_mut()[before_n..];

                    let cipher = self.cipher.as_mut().expect("cipher is None");
                    if !cipher.decrypt_packet(m) {
                        return Err(ProtocolError::DecryptError).into();
                    }

                    return Ok(()).into();
                }
            }
        }
    }

    fn poll_read_iv<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        key: &[u8],
    ) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let iv_len = self.method.iv_len();

        let n = ready!(self.poll_read_exact(cx, stream, iv_len))?;
        if n < iv_len {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
        }

        let iv = &self.buffer[..iv_len];
        context.check_nonce_replay(self.method, iv)?;

        trace!("got stream iv {:?}", ByteStr::new(iv));

        // Stores IV
        self.iv = Some(Bytes::copy_from_slice(iv));

        let cipher = Cipher::new(self.method, key, iv);
        self.cipher = Some(cipher);

        Ok(()).into()
    }

    fn poll_read_exact<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, size: usize) -> Poll<io::Result<usize>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        assert!(size != 0);

        while self.buffer.len() < size {
            let remaining = size - self.buffer.len();
            let buffer = &mut self.buffer.chunk_mut()[..remaining];

            let mut read_buf =
                ReadBuf::uninit(unsafe { slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut _, remaining) });
            ready!(Pin::new(&mut *stream).poll_read(cx, &mut read_buf))?;

            let n = read_buf.filled().len();
            if n == 0 {
                if !self.buffer.is_empty() {
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                } else {
                    return Ok(0).into();
                }
            }

            unsafe {
                self.buffer.advance_mut(n);
            }
        }

        Ok(size).into()
    }

    /// Check if handshake finished
    pub fn handshaked(&self) -> bool {
        self.has_handshaked
    }
}

enum EncryptWriteState {
    AssemblePacket,
    /// `plain_len` records the length of the plaintext buffer that was assembled into the
    /// pending ciphertext buffer. It must be reported back to the caller when the buffer is
    /// fully sent, because the caller is allowed to retry `poll_write_encrypted` with a
    /// longer buffer after `Poll::Pending` (e.g. tokio's `copy` appending freshly read data).
    /// Only the bytes counted by `plain_len` were actually consumed.
    Writing { pos: usize, plain_len: usize },
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher: Cipher,
    buffer: BytesMut,
    state: EncryptWriteState,
    iv: Bytes,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> Self {
        // nonce should be sent with the first packet
        let mut buffer = BytesMut::with_capacity(nonce.len());
        buffer.put(nonce);

        Self {
            cipher: Cipher::new(method, key, nonce),
            buffer,
            state: EncryptWriteState::AssemblePacket,
            iv: Bytes::copy_from_slice(nonce),
        }
    }

    /// IV
    pub fn iv(&self) -> &[u8] {
        self.iv.as_ref()
    }

    /// Attempt to write encrypted data into the writer
    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut S,
        buf: &[u8],
    ) -> Poll<ProtocolResult<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            match self.state {
                EncryptWriteState::AssemblePacket => {
                    let n = self.buffer.len();
                    self.buffer.put_slice(buf);
                    self.cipher.encrypt_packet(&mut self.buffer[n..]);
                    self.state = EncryptWriteState::Writing {
                        pos: 0,
                        plain_len: buf.len(),
                    };
                }
                EncryptWriteState::Writing { ref mut pos, plain_len } => {
                    while *pos < self.buffer.len() {
                        let n = ready!(Pin::new(&mut *stream).poll_write(cx, &self.buffer[*pos..]))?;
                        if n == 0 {
                            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
                        }
                        *pos += n;
                    }

                    // Reset state
                    self.state = EncryptWriteState::AssemblePacket;
                    self.buffer.clear();

                    // Only the plaintext bytes that were assembled into this buffer have been sent.
                    // The caller may retry with a longer buffer after `Poll::Pending`, and those
                    // extra bytes have NOT been encrypted into this buffer yet.
                    return Ok(plain_len).into();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context as TaskContext, Poll as TaskPoll, Waker},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    /// An `AsyncWrite` sink that can be blocked to simulate backpressure,
    /// replayable as an `AsyncRead` source for verifying the round-trip.
    struct TestStream {
        blocked: bool,
        bytes: Vec<u8>,
        read_pos: usize,
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            data: &[u8],
        ) -> TaskPoll<io::Result<usize>> {
            if self.blocked {
                return TaskPoll::Pending;
            }
            self.bytes.extend_from_slice(data);
            TaskPoll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> TaskPoll<io::Result<()>> {
            TaskPoll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> TaskPoll<io::Result<()>> {
            TaskPoll::Ready(Ok(()))
        }
    }

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> TaskPoll<io::Result<()>> {
            if self.read_pos < self.bytes.len() {
                let remaining = &self.bytes[self.read_pos..];
                let n = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..n]);
                self.read_pos += n;
            }
            TaskPoll::Ready(Ok(()))
        }
    }

    // Regression test for https://github.com/shadowsocks/shadowsocks-rust/issues/2175
    //
    // The writer must report the plaintext length that was actually encrypted into the
    // pending buffer, instead of the length of the buffer passed on the retried call.
    // Otherwise, bytes appended by the caller while the writer was `Poll::Pending`
    // (as tokio's `copy` does) would be silently dropped.
    #[test]
    fn test_retry_after_pending_with_longer_buffer() {
        let context = Context::new_shared(crate::config::ServerType::Server);

        let key = [0x42u8; 16];
        let nonce = [0x24u8; 16];
        let method = CipherKind::AES_128_CFB128;

        let mut writer = EncryptedWriter::new(method, &key, &nonce);

        let mut stream = TestStream {
            blocked: true,
            bytes: Vec::new(),
            read_pos: 0,
        };

        let mut cx = TaskContext::from_waker(Waker::noop());

        // 1st attempt: the underlying stream is blocked, so the writer must return Pending.
        assert!(
            writer
                .poll_write_encrypted(&mut cx, &mut stream, b"a")
                .is_pending()
        );

        // The underlying stream becomes writable.
        stream.blocked = false;

        // 2nd attempt: the caller retries with a longer buffer, like tokio's
        // `copy`/`copy_bidirectional` appending freshly read data while waiting.
        // Only "a" was encrypted into the pending buffer, so only 1 byte may be reported.
        match writer.poll_write_encrypted(&mut cx, &mut stream, b"ab") {
            TaskPoll::Ready(Ok(n)) => assert_eq!(n, 1),
            v => panic!("unexpected result: {v:?}"),
        }

        // The caller advances by the reported length and submits the remaining bytes.
        match writer.poll_write_encrypted(&mut cx, &mut stream, b"b") {
            TaskPoll::Ready(Ok(n)) => assert_eq!(n, 1),
            v => panic!("unexpected result: {v:?}"),
        }

        // Round-trip: everything reported as written must decrypt back to the original bytes.
        let mut reader = DecryptedReader::new(method, &key);
        let mut output = Vec::new();
        loop {
            let mut buffer = [0u8; 16];
            let mut read_buf = ReadBuf::new(&mut buffer);
            match reader.poll_read_decrypted(&mut cx, &context, &mut stream, &mut read_buf) {
                TaskPoll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        // EOF
                        break;
                    }
                    output.extend_from_slice(read_buf.filled());
                }
                v => panic!("unexpected read result: {v:?}"),
            }
        }

        assert_eq!(output, b"ab");
    }
}
