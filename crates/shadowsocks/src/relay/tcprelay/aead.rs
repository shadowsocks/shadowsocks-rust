//! AEAD packet I/O facilities
//!
//! AEAD protocol is defined in <https://shadowsocks.org/doc/aead.html>.
//!
//! ```plain
//! TCP request (before encryption)
//! +------+---------------------+------------------+
//! | ATYP | Destination Address | Destination Port |
//! +------+---------------------+------------------+
//! |  1   |       Variable      |         2        |
//! +------+---------------------+------------------+
//!
//! TCP request (after encryption, *ciphertext*)
//! +--------+--------------+------------------+--------------+---------------+
//! | NONCE  |  *HeaderLen* |   HeaderLen_TAG  |   *Header*   |  Header_TAG   |
//! +--------+--------------+------------------+--------------+---------------+
//! | Fixed  |       2      |       Fixed      |   Variable   |     Fixed     |
//! +--------+--------------+------------------+--------------+---------------+
//!
//! TCP Chunk (before encryption)
//! +----------+
//! |  DATA    |
//! +----------+
//! | Variable |
//! +----------+
//!
//! TCP Chunk (after encryption, *ciphertext*)
//! +--------------+---------------+--------------+------------+
//! |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
//! +--------------+---------------+--------------+------------+
//! |      2       |     Fixed     |   Variable   |   Fixed    |
//! +--------------+---------------+--------------+------------+
//! ```
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

/// AEAD packet payload must be smaller than 0x3FFF
pub const MAX_PACKET_SIZE: usize = 0x3FFF;

/// AEAD Protocol Error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("header too short, expecting {0} bytes, but found {1} bytes")]
    HeaderTooShort(usize, usize),
    #[error("decrypt data failed")]
    DecryptDataError,
    #[error("decrypt length failed")]
    DecryptLengthError,
    #[error(
        "buffer size too large ({0:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero"
    )]
    DataTooLong(usize),
}

/// AEAD Protocol result
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<ProtocolError> for io::Error {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::IoError(err) => err,
            _ => Self::other(e),
        }
    }
}

#[derive(Debug)]
enum DecryptReadState {
    WaitSalt { key: Bytes },
    ReadLength,
    ReadData { length: usize },
    BufferedData { pos: usize },
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    state: DecryptReadState,
    cipher: Option<Cipher>,
    buffer: BytesMut,
    method: CipherKind,
    salt: Option<Bytes>,
    has_handshaked: bool,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8]) -> Self {
        if method.salt_len() > 0 {
            Self {
                state: DecryptReadState::WaitSalt {
                    key: Bytes::copy_from_slice(key),
                },
                cipher: None,
                buffer: BytesMut::with_capacity(method.salt_len()),
                method,
                salt: None,
                has_handshaked: false,
            }
        } else {
            Self {
                state: DecryptReadState::ReadLength,
                cipher: Some(Cipher::new(method, key, &[])),
                buffer: BytesMut::with_capacity(2 + method.tag_len()),
                method,
                salt: None,
                has_handshaked: false,
            }
        }
    }

    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    /// Attempt to read decrypted data from stream
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
                DecryptReadState::WaitSalt { ref key } => {
                    let key = unsafe { &*(key.as_ref() as *const _) };
                    ready!(self.poll_read_salt(cx, stream, key))?;

                    self.buffer.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buffer.reserve(2 + self.method.tag_len());
                    self.has_handshaked = true;
                }
                DecryptReadState::ReadLength => match ready!(self.poll_read_length(cx, stream))? {
                    None => {
                        return Ok(()).into();
                    }
                    Some(length) => {
                        self.buffer.clear();
                        self.state = DecryptReadState::ReadData { length };
                        self.buffer.reserve(length + self.method.tag_len());
                    }
                },
                DecryptReadState::ReadData { length } => {
                    ready!(self.poll_read_data(cx, context, stream, length))?;

                    self.state = DecryptReadState::BufferedData { pos: 0 };
                }
                DecryptReadState::BufferedData { ref mut pos } => {
                    if *pos < self.buffer.len() {
                        let buffered = &self.buffer[*pos..];

                        let consumed = usize::min(buffered.len(), buf.remaining());
                        buf.put_slice(&buffered[..consumed]);

                        *pos += consumed;

                        return Ok(()).into();
                    }

                    self.buffer.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buffer.reserve(2 + self.method.tag_len());
                }
            }
        }
    }

    fn poll_read_salt<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, key: &[u8]) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let salt_len = self.method.salt_len();

        let n = ready!(self.poll_read_exact(cx, stream, salt_len))?;
        if n < salt_len {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
        }

        let salt = &self.buffer[..salt_len];
        // #442 Remember salt in filter after first successful decryption.
        //
        // If we check salt right here will allow attacker to flood our filter and eventually block all of our legitimate clients' requests.
        self.salt = Some(Bytes::copy_from_slice(salt));

        trace!("got AEAD salt {:?}", ByteStr::new(salt));

        let cipher = Cipher::new(self.method, key, salt);

        self.cipher = Some(cipher);

        Ok(()).into()
    }

    fn poll_read_length<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S) -> Poll<ProtocolResult<Option<usize>>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let length_len = 2 + self.method.tag_len();

        let n = ready!(self.poll_read_exact(cx, stream, length_len))?;
        if n == 0 {
            return Ok(None).into();
        }

        let cipher = self.cipher.as_mut().expect("cipher is None");

        let m = &mut self.buffer[..length_len];
        let length = Self::decrypt_length(cipher, m)?;

        Ok(Some(length)).into()
    }

    fn poll_read_data<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        size: usize,
    ) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let data_len = size + self.method.tag_len();

        let n = ready!(self.poll_read_exact(cx, stream, data_len))?;
        if n == 0 {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
        }

        let cipher = self.cipher.as_mut().expect("cipher is None");

        let m = &mut self.buffer[..data_len];
        if !cipher.decrypt_packet(m) {
            return Err(ProtocolError::DecryptDataError).into();
        }

        // Check repeated salt after first successful decryption #442
        if self.salt.is_some() {
            let salt = self.salt.take().unwrap();
            context.check_nonce_replay(self.method, &salt)?;
        }

        // Remote TAG
        self.buffer.truncate(size);

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

    fn decrypt_length(cipher: &mut Cipher, m: &mut [u8]) -> ProtocolResult<usize> {
        let plen = {
            if !cipher.decrypt_packet(m) {
                return Err(ProtocolError::DecryptLengthError);
            }

            u16::from_be_bytes([m[0], m[1]]) as usize
        };

        if plen > MAX_PACKET_SIZE {
            // https://shadowsocks.org/doc/aead.html
            //
            // AEAD TCP protocol have reserved the higher two bits for future use
            return Err(ProtocolError::DataTooLong(plen));
        }

        Ok(plen)
    }

    /// Check if handshake finished
    pub fn handshaked(&self) -> bool {
        self.has_handshaked
    }
}

#[derive(Debug)]
enum EncryptWriteState {
    AssemblePacket,
    /// `plain_len` records the length of the plaintext buffer that was assembled into the
    /// pending ciphertext frame. It must be reported back to the caller when the frame is
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
    salt: Bytes,
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
            salt: Bytes::copy_from_slice(nonce),
        }
    }

    /// Salt (nonce)
    pub fn salt(&self) -> &[u8] {
        self.salt.as_ref()
    }

    /// Attempt to write encrypted data into the writer
    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut S,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        if buf.len() > MAX_PACKET_SIZE {
            buf = &buf[..MAX_PACKET_SIZE];
        }

        loop {
            match self.state {
                EncryptWriteState::AssemblePacket => {
                    // Step 1. Append Length
                    let length_size = 2 + self.cipher.tag_len();
                    self.buffer.reserve(length_size);

                    let mbuf = &mut self.buffer.chunk_mut()[..length_size];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    self.buffer.put_u16(buf.len() as u16);
                    self.cipher.encrypt_packet(mbuf);
                    unsafe { self.buffer.advance_mut(self.cipher.tag_len()) };

                    // Step 2. Append data
                    let data_size = buf.len() + self.cipher.tag_len();
                    self.buffer.reserve(data_size);

                    let mbuf = &mut self.buffer.chunk_mut()[..data_size];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    self.buffer.put_slice(buf);
                    self.cipher.encrypt_packet(mbuf);
                    unsafe { self.buffer.advance_mut(self.cipher.tag_len()) };

                    // Step 3. Write all
                    self.state = EncryptWriteState::Writing {
                        pos: 0,
                        plain_len: buf.len(),
                    };
                }
                EncryptWriteState::Writing { ref mut pos, plain_len } => {
                    while *pos < self.buffer.len() {
                        let n = ready!(Pin::new(&mut *stream).poll_write(cx, &self.buffer[*pos..]))?;
                        if n == 0 {
                            return Err(ErrorKind::UnexpectedEof.into()).into();
                        }
                        *pos += n;
                    }

                    // Reset state
                    self.state = EncryptWriteState::AssemblePacket;
                    self.buffer.clear();

                    // Only the plaintext bytes that were assembled into this frame have been sent.
                    // The caller may retry with a longer buffer after `Poll::Pending`, and those
                    // extra bytes have NOT been encrypted into this frame yet.
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
    // pending frame, instead of the length of the buffer passed on the retried call.
    // Otherwise, bytes appended by the caller while the writer was `Poll::Pending`
    // (as tokio's `copy` does) would be silently dropped.
    #[test]
    fn test_retry_after_pending_with_longer_buffer() {
        let context = Context::new_shared(crate::config::ServerType::Server);

        let key = [0x42u8; 16];
        let nonce = [0x24u8; 16];
        let method = CipherKind::AES_128_GCM;

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
        // Only "a" was encrypted into the pending frame, so only 1 byte may be reported.
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
