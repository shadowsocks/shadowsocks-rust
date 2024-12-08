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
    sync::Arc,
    task::{self, Poll},
    time::SystemTime,
};

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Aes256, Block,
};
use byte_string::ByteStr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::ready;
use log::{error, trace};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{crypto_io::StreamType, proxy_stream::protocol::v2::SERVER_STREAM_TIMESTAMP_MAX_DIFF};
use crate::{
    config::{method_support_eih, ServerUserManager},
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

const AEAD2022_EIH_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";

/// AEAD 2022 Protocol Error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("header too short, expecting {0} bytes, but found {1} bytes")]
    HeaderTooShort(usize, usize),
    #[error("missing extended identity header")]
    MissingExtendedIdentityHeader,
    #[error("invalid client user identity {:?}", ByteStr::new(.0))]
    InvalidClientUser(Bytes),
    #[error("decrypt header chunk failed")]
    DecryptHeaderChunkError,
    #[error("decrypt data failed")]
    DecryptDataError,
    #[error("decrypt length failed")]
    DecryptLengthError,
    #[error("invalid stream type, expecting {0:#x}, but found {1:#x}")]
    InvalidStreamType(u8, u8),
    #[error("invalid timestamp {0} - now {1} = {ts_diff}", ts_diff = *.0 as i64 - *.1 as i64)]
    InvalidTimestamp(u64, u64),
}

/// AEAD 2022 Protocol result
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<ProtocolError> for io::Error {
    fn from(e: ProtocolError) -> io::Error {
        match e {
            ProtocolError::IoError(err) => err,
            _ => io::Error::new(ErrorKind::Other, e),
        }
    }
}

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
    user_manager: Option<Arc<ServerUserManager>>,
    user_key: Option<Bytes>,
    has_handshaked: bool,
}

impl DecryptedReader {
    pub fn new(stream_ty: StreamType, method: CipherKind, key: &[u8]) -> DecryptedReader {
        DecryptedReader::with_user_manager(stream_ty, method, key, None)
    }

    pub fn with_user_manager(
        stream_ty: StreamType,
        method: CipherKind,
        key: &[u8],
        user_manager: Option<Arc<ServerUserManager>>,
    ) -> DecryptedReader {
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
                user_manager,
                user_key: None,
                has_handshaked: false,
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
                user_manager,
                user_key: None,
                has_handshaked: false,
            }
        }
    }

    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    pub fn request_salt(&self) -> Option<&[u8]> {
        self.request_salt.as_deref().filter(|&n| !n.is_empty())
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
                            self.has_handshaked = true;
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
    ) -> Poll<ProtocolResult<Option<usize>>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let salt_len = self.method.salt_len();

        // Header chunk, SALE + AEAD(TYPE + TIMESTAMP [+ REQUEST_SALT] + LENGTH) must be read in one call
        let request_salt_len = match self.stream_ty {
            StreamType::Client => salt_len,
            StreamType::Server => 0,
        };
        let require_eih =
            self.stream_ty == StreamType::Server && method_support_eih(self.method) && self.user_manager.is_some();
        let eih_len = if require_eih { 16 } else { 0 };
        let header_len = salt_len + eih_len + 1 + 8 + request_salt_len + 2 + self.method.tag_len();
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
            return Err(ProtocolError::HeaderTooShort(header_len, header_buf.len())).into();
        }

        let (salt, mut header_chunk) = header_buf.split_at_mut(salt_len);

        trace!("got AEAD salt {:?}", ByteStr::new(salt));

        // Extensible Identity Header
        // https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
        let mut cipher = if require_eih {
            if let Some(ref user_manager) = self.user_manager {
                // Assume we have at least 1 EIH
                if header_chunk.len() < 16 {
                    error!("expecting EIH, but header chunk len: {}", header_chunk.len());
                    return Err(ProtocolError::MissingExtendedIdentityHeader).into();
                }

                let (eih, remain_header_chunk) = header_chunk.split_at_mut(16);
                header_chunk = remain_header_chunk;

                let key_material = [key, salt].concat();
                let identity_sub_key = blake3::derive_key(AEAD2022_EIH_SUBKEY_CONTEXT, &key_material);
                let mut user_hash = Block::from([0u8; 16]);
                match self.method {
                    CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                        let cipher = Aes128::new_from_slice(&identity_sub_key[0..16]).expect("AES-128");
                        cipher.decrypt_block_b2b(Block::from_slice(eih), &mut user_hash);
                    }
                    CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                        let cipher = Aes256::new_from_slice(&identity_sub_key[0..32]).expect("AES-256");
                        cipher.decrypt_block_b2b(Block::from_slice(eih), &mut user_hash);
                    }
                    _ => unreachable!("{} doesn't support EIH", self.method),
                }

                let user_hash = user_hash.as_slice();
                trace!(
                    "server EIH {:?}, hash: {:?}",
                    ByteStr::new(eih),
                    ByteStr::new(user_hash)
                );

                match user_manager.get_user_by_hash(user_hash) {
                    None => {
                        return Err(ProtocolError::InvalidClientUser(Bytes::copy_from_slice(user_hash))).into();
                    }
                    Some(user) => {
                        trace!("{:?} chosen by EIH", user);
                        self.user_key = Some(Bytes::copy_from_slice(user.key()));
                        TcpCipher::new(self.method, user.key(), salt)
                    }
                }
            } else {
                unreachable!("user_manager must not be None")
            }
        } else {
            TcpCipher::new(self.method, key, salt)
        };

        // Decrypt the header chunk
        if !cipher.decrypt_packet(header_chunk) {
            return Err(ProtocolError::DecryptHeaderChunkError).into();
        }

        let mut header_reader = Cursor::new(header_chunk);

        let stream_ty = header_reader.get_u8();
        let expected_stream_ty = match self.stream_ty {
            StreamType::Client => 1, // Receive from server, so type == SERVER (1)
            StreamType::Server => 0,
        };
        if stream_ty != expected_stream_ty {
            return Err(ProtocolError::InvalidStreamType(expected_stream_ty, stream_ty)).into();
        }

        let timestamp = header_reader.get_u64();
        let now = get_now_timestamp();
        if now.abs_diff(timestamp) > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
            return Err(ProtocolError::InvalidTimestamp(timestamp, now)).into();
        }

        // Server respond packet will contain a request salt
        if request_salt_len > 0 {
            let mut request_salt = BytesMut::with_capacity(salt_len);
            request_salt.resize(salt_len, 0);
            header_reader.read_exact(&mut request_salt)?;
            self.request_salt = Some(request_salt.freeze());
        }

        let data_length = header_reader.get_u16();

        trace!(
            "got AEAD header stream_type: {}, timestamp: {}, length: {}, request_salt: {:?}",
            stream_ty,
            timestamp,
            data_length,
            self.request_salt.as_deref().map(ByteStr::new)
        );

        // Salt doesn't need to be checked in client, because it has request_salt in respond header
        if self.stream_ty == StreamType::Server {
            // Check repeated salt after first successful decryption #442
            //
            // If we check salt right here will allow attacker to flood our filter and eventually block all of our legitimate clients' requests.

            context.check_nonce_replay(self.method, salt)?;
        }

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

    fn poll_read_data<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, size: usize) -> Poll<ProtocolResult<()>>
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

    fn decrypt_length(cipher: &mut TcpCipher, m: &mut [u8]) -> ProtocolResult<usize> {
        let plen = {
            if !cipher.decrypt_packet(m) {
                return Err(ProtocolError::DecryptLengthError);
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

    /// Get authenticated user key
    pub fn user_key(&self) -> Option<&[u8]> {
        self.user_key.as_deref()
    }

    /// Check if handshake finished
    pub fn handshaked(&self) -> bool {
        self.has_handshaked
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
    method: CipherKind,
    buffer: BytesMut,
    state: EncryptWriteState,
    salt: Bytes,
    request_salt: Option<Bytes>,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(stream_ty: StreamType, method: CipherKind, key: &[u8], nonce: &[u8]) -> EncryptedWriter {
        const EMPTY_IDENTITY: [Bytes; 0] = [];
        EncryptedWriter::with_identity(stream_ty, method, key, nonce, &EMPTY_IDENTITY)
    }

    /// Creates a new EncryptedWriter with identities
    pub fn with_identity(
        stream_ty: StreamType,
        method: CipherKind,
        key: &[u8],
        nonce: &[u8],
        identity_keys: &[Bytes],
    ) -> EncryptedWriter {
        // nonce should be sent with the first packet
        let mut buffer = BytesMut::with_capacity(nonce.len() + identity_keys.len() * 16);
        buffer.put(nonce);

        // Extensible Identity Headers
        // https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
        #[inline]
        fn make_eih(method: CipherKind, sub_key: &[u8], ipsk: &[u8], buffer: &mut BytesMut) {
            let ipsk_hash = blake3::hash(ipsk);
            let ipsk_plain_text = &ipsk_hash.as_bytes()[0..16];

            match method {
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                    let enc_key = &sub_key[0..16];
                    let cipher = Aes128::new_from_slice(enc_key).expect("AES-128");

                    let ipsk_plain_text = Block::from_slice(ipsk_plain_text);
                    let mut block = Block::from([0u8; 16]);
                    cipher.encrypt_block_b2b(ipsk_plain_text, &mut block);

                    trace!(
                        "client EIH {:?}, hash: {:?}",
                        ByteStr::new(block.as_slice()),
                        ByteStr::new(ipsk_plain_text)
                    );
                    buffer.put(block.as_slice());
                }
                CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                    let enc_key = &sub_key[0..32];
                    let cipher = Aes256::new_from_slice(enc_key).expect("AES-256");

                    let ipsk_plain_text = Block::from_slice(ipsk_plain_text);
                    let mut block = Block::from([0u8; 16]);
                    cipher.encrypt_block_b2b(ipsk_plain_text, &mut block);

                    trace!(
                        "client EIH {:?}, hash: {:?}",
                        ByteStr::new(block.as_slice()),
                        ByteStr::new(ipsk_plain_text)
                    );
                    buffer.put(block.as_slice());
                }
                _ => unreachable!("{} doesn't support EIH", method),
            }
        }

        if stream_ty == StreamType::Client && method_support_eih(method) {
            let mut sub_key: Option<[u8; blake3::OUT_LEN]> = None;

            for ipsk in identity_keys {
                if let Some(ref sub_key) = sub_key {
                    make_eih(method, sub_key, ipsk, &mut buffer);
                }

                let key_material = [ipsk, nonce].concat();
                sub_key = Some(blake3::derive_key(AEAD2022_EIH_SUBKEY_CONTEXT, &key_material));
            }

            if let Some(ref sub_key) = sub_key {
                make_eih(method, sub_key, key, &mut buffer);
            }
        }

        EncryptedWriter {
            stream_ty,
            cipher: TcpCipher::new(method, key, nonce),
            method,
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

    /// Reset cipher with key
    pub fn reset_cipher_with_key(&mut self, key: &[u8]) {
        self.cipher = TcpCipher::new(self.method, key, &self.salt);
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
