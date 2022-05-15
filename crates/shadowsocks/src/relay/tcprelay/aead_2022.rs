//! AEAD 2022 packet I/O facilities
//!
//! ```plain
//! TCP Header (before encryption)
//!
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+
//! | TYPE   | TIMESTAMP (BE)                                                        |
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+
//! | ATYP   | ADDRESS ... (Variable Length ...)
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+
//! | PORT (BE)       | Paddding Length | Padding (Variable Length ...)
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+
//!
//! TCP Request Header (after encryption, *ciphertext*)
//!
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | SALT (Variable Length ...)
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
//! | AEAD (TYPE + TIMESTAMP + HEADER_LENGTH)                                                          |
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
//! | AEAD (ATYP + ADDRESS + PORT + PADDING_LENGTH + PADDING)
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
//!
//! TCP Respond Header (after encryption, *ciphertext*)
//!
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | SALT (Variable Length ...)
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
//! | AEAD (TYPE + TIMESTAMP + REQUEST_SALT + DATA_LENGTH)
//! +--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
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
    io::{self, Cursor, ErrorKind, Read},
    marker::Unpin,
    pin::Pin,
    slice,
    task::{self, Poll},
    time::SystemTime,
    u16,
};

use byte_string::ByteStr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::ready;
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{crypto_io::StreamType, proxy_stream::protocol::v2::SERVER_STREAM_TIMESTAMP_MAX_DIFF};
use crate::{
    context::Context,
    crypto::{v2::tcp::TcpCipher, CipherKind},
};

#[inline]
fn get_now_timestamp() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime::now() is before UNIX Epoch!"),
    }
}

/// AEAD packet payload must be smaller than 0xFFFF (u16::MAX)
pub const MAX_PACKET_SIZE: usize = 0xFFFF;

enum DecryptReadState {
    ReadHeader { key: Bytes },
    ReadLength,
    ReadData { length: usize },
    BufferedData { pos: usize },
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    stream_ty: StreamType,
    state: DecryptReadState,
    cipher: Option<TcpCipher>,
    buffer: BytesMut,
    method: CipherKind,
    salt: Option<Bytes>,
    request_salt: Option<Bytes>,
    data_chunk_count: u64,
}

impl DecryptedReader {
    pub fn new(stream_ty: StreamType, method: CipherKind, key: &[u8]) -> DecryptedReader {
        if method.salt_len() > 0 {
            DecryptedReader {
                stream_ty,
                state: DecryptReadState::ReadHeader {
                    key: Bytes::copy_from_slice(key),
                },
                cipher: None,
                buffer: BytesMut::new(),
                method,
                salt: None,
                request_salt: None,
                data_chunk_count: 0,
            }
        } else {
            DecryptedReader {
                stream_ty,
                state: DecryptReadState::ReadHeader {
                    key: Bytes::new(), // EMPTY SALT, no allocation
                },
                cipher: Some(TcpCipher::new(method, key, &[])),
                buffer: BytesMut::new(),
                method,
                salt: None,
                request_salt: None,
                data_chunk_count: 0,
            }
        }
    }

    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    pub fn request_salt(&self) -> Option<&[u8]> {
        match self.request_salt.as_deref() {
            Some(n) => {
                if n.is_empty() {
                    None
                } else {
                    Some(n)
                }
            }
            None => None,
        }
    }

    /// Attempt to read decrypted data from stream
    pub fn poll_read_decrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.state {
                DecryptReadState::ReadHeader { ref key } => {
                    let key = unsafe { &*(key.as_ref() as *const _) };
                    match ready!(self.poll_read_header(cx, context, stream, key))? {
                        None => {
                            return Ok(()).into();
                        }
                        Some(length) => {
                            self.buffer.clear();
                            self.state = DecryptReadState::ReadData { length };
                            self.buffer.reserve(length + self.method.tag_len());
                        }
                    }
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
                    ready!(self.poll_read_data(cx, stream, length))?;

                    self.state = DecryptReadState::BufferedData { pos: 0 };
                    self.data_chunk_count = self.data_chunk_count.wrapping_add(1);
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

    fn poll_read_header<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        key: &[u8],
    ) -> Poll<io::Result<Option<usize>>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let salt_len = self.method.salt_len();

        // Header chunk, SALE + AEAD(TYPE + TIMESTAMP [+ REQUEST_SALT] + LENGTH) must be read in one call
        let request_salt_len = match self.stream_ty {
            StreamType::Client => salt_len,
            StreamType::Server => 0,
        };
        let header_len = salt_len + 1 + 8 + request_salt_len + 2 + self.method.tag_len();
        if self.buffer.len() < header_len {
            self.buffer.resize(header_len, 0);
        }
        let mut read_buf = ReadBuf::new(&mut self.buffer[..header_len]);
        ready!(Pin::new(stream).poll_read(cx, &mut read_buf))?;
        let header_buf = read_buf.filled_mut();
        if header_buf.is_empty() {
            // EOF.
            return Ok(None).into();
        } else if header_buf.len() != header_len {
            return Err(io::Error::new(ErrorKind::InvalidData, "header too short")).into();
        }

        let (salt, header_chunk) = header_buf.split_at_mut(salt_len);

        trace!("got AEAD salt {:?}", ByteStr::new(salt));

        let mut cipher = TcpCipher::new(self.method, key, salt);

        // Decrypt the header chunk
        if !cipher.decrypt_packet(header_chunk) {
            return Err(io::Error::new(ErrorKind::Other, "invalid tag-in")).into();
        }

        let mut header_reader = Cursor::new(header_chunk);

        let stream_ty = header_reader.get_u8();
        let expected_stream_ty = match self.stream_ty {
            StreamType::Client => 1, // Receive from server, so type == SERVER (1)
            StreamType::Server => 0,
        };
        if stream_ty != expected_stream_ty {
            return Err(io::Error::new(ErrorKind::Other, "invalid stream type")).into();
        }

        let timestamp = header_reader.get_u64();
        let now = get_now_timestamp();
        if now.abs_diff(timestamp) > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("received TCP request header with aged timestamp: {}", timestamp),
            ))
            .into();
        }

        // Server respond packet will contain a request salt
        if request_salt_len > 0 {
            let mut request_salt = BytesMut::with_capacity(salt_len);
            request_salt.resize(salt_len, 0);
            header_reader.read_exact(&mut request_salt)?;
            self.request_salt = Some(request_salt.freeze());
        }

        let data_length = header_reader.get_u16();

        // Check repeated salt after first successful decryption #442
        //
        // If we check salt right here will allow attacker to flood our filter and eventually block all of our legitimate clients' requests.
        context.check_nonce_replay(self.method, salt)?;
        self.salt = Some(Bytes::copy_from_slice(salt));

        self.cipher = Some(cipher);
        Ok(Some(data_length as usize)).into()
    }

    fn poll_read_length<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S) -> Poll<io::Result<Option<usize>>>
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
        let length = DecryptedReader::decrypt_length(cipher, m)?;

        Ok(Some(length)).into()
    }

    fn poll_read_data<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, size: usize) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let data_len = size + self.method.tag_len();

        let n = ready!(self.poll_read_exact(cx, stream, data_len))?;
        if n == 0 {
            return Err(ErrorKind::UnexpectedEof.into()).into();
        }

        let cipher = self.cipher.as_mut().expect("cipher is None");

        let m = &mut self.buffer[..data_len];
        if !cipher.decrypt_packet(m) {
            return Err(io::Error::new(ErrorKind::Other, "invalid tag-in")).into();
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

    fn decrypt_length(cipher: &mut TcpCipher, m: &mut [u8]) -> io::Result<usize> {
        let plen = {
            if !cipher.decrypt_packet(m) {
                return Err(io::Error::new(ErrorKind::Other, "invalid tag-in"));
            }

            u16::from_be_bytes([m[0], m[1]]) as usize
        };

        Ok(plen)
    }

    /// Get remaining bytes in the current data chunk
    ///
    /// Returning (DataChunkCount, RemainingBytes)
    pub fn current_data_chunk_remaining(&self) -> (u64, usize) {
        match self.state {
            DecryptReadState::BufferedData { pos } => (self.data_chunk_count, self.buffer.len() - pos),
            _ => (self.data_chunk_count, 0),
        }
    }
}

enum EncryptWriteState {
    AssembleHeader,
    AssemblePacket,
    Writing { pos: usize },
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    stream_ty: StreamType,
    cipher: TcpCipher,
    buffer: BytesMut,
    state: EncryptWriteState,
    salt: Bytes,
    request_salt: Option<Bytes>,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(stream_ty: StreamType, method: CipherKind, key: &[u8], nonce: &[u8]) -> EncryptedWriter {
        // nonce should be sent with the first packet
        let mut buffer = BytesMut::with_capacity(nonce.len());
        buffer.put(nonce);

        EncryptedWriter {
            stream_ty,
            cipher: TcpCipher::new(method, key, nonce),
            buffer,
            state: EncryptWriteState::AssembleHeader,
            salt: Bytes::copy_from_slice(nonce),
            request_salt: None,
        }
    }

    /// Salt (nonce)
    pub fn salt(&self) -> &[u8] {
        self.salt.as_ref()
    }

    /// Set request salt (for server stream type)
    pub fn set_request_salt(&mut self, request_salt: Bytes) {
        debug_assert!(self.stream_ty == StreamType::Server);
        self.request_salt = Some(request_salt);
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
                EncryptWriteState::AssembleHeader => {
                    // Step 1. AEAD(TYPE + TIMESTAMP [+ REQUEST_SALT] + LENGTH)
                    let request_salt_len = match self.request_salt {
                        None => 0,
                        Some(ref salt) => salt.len(),
                    };
                    let header_len = 1 + 8 + request_salt_len + 2 + self.cipher.tag_len();
                    self.buffer.reserve(header_len);

                    let mbuf = &mut self.buffer.chunk_mut()[..header_len];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    let stream_ty = match self.stream_ty {
                        StreamType::Client => 0,
                        StreamType::Server => 1,
                    };
                    self.buffer.put_u8(stream_ty);
                    self.buffer.put_u64(get_now_timestamp());
                    if let Some(ref salt) = self.request_salt {
                        self.buffer.put_slice(salt);
                    }
                    self.buffer.put_u16(buf.len() as u16);
                    self.cipher.encrypt_packet(mbuf);
                    unsafe { self.buffer.advance_mut(self.cipher.tag_len()) };

                    // Step 2. Data Chunk
                    let data_size = buf.len() + self.cipher.tag_len();
                    self.buffer.reserve(data_size);

                    let mbuf = &mut self.buffer.chunk_mut()[..data_size];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    self.buffer.put_slice(buf);
                    self.cipher.encrypt_packet(mbuf);
                    unsafe { self.buffer.advance_mut(self.cipher.tag_len()) };

                    // Step 3. Write all
                    self.state = EncryptWriteState::Writing { pos: 0 };
                }

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
                    self.state = EncryptWriteState::Writing { pos: 0 };
                }
                EncryptWriteState::Writing { ref mut pos } => {
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

                    return Ok(buf.len()).into();
                }
            }
        }
    }
}
