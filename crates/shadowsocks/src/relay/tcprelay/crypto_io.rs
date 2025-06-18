//! IO facilities for TCP relay

use std::{
    fmt, io,
    marker::Unpin,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

#[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
use byte_string::ByteStr;
use bytes::Bytes;
use futures::ready;
#[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    config::ServerUserManager,
    context::Context,
    crypto::{CipherCategory, CipherKind},
};

#[cfg(feature = "aead-cipher")]
use super::aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter};
#[cfg(feature = "aead-cipher-2022")]
use super::aead_2022::{DecryptedReader as Aead2022DecryptedReader, EncryptedWriter as Aead2022EncryptedWriter};
#[cfg(feature = "stream-cipher")]
use super::stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter};

/// TCP shadowsocks protocol error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[cfg(feature = "stream-cipher")]
    #[error(transparent)]
    StreamError(#[from] super::stream::ProtocolError),
    #[cfg(feature = "aead-cipher")]
    #[error(transparent)]
    AeadError(#[from] super::aead::ProtocolError),
    #[cfg(feature = "aead-cipher-2022")]
    #[error(transparent)]
    Aead2022Error(#[from] super::aead_2022::ProtocolError),
}

/// TCP shadowsocks protocol result
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<ProtocolError> for io::Error {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::IoError(err) => err,
            #[cfg(feature = "stream-cipher")]
            ProtocolError::StreamError(err) => err.into(),
            #[cfg(feature = "aead-cipher")]
            ProtocolError::AeadError(err) => err.into(),
            #[cfg(feature = "aead-cipher-2022")]
            ProtocolError::Aead2022Error(err) => err.into(),
        }
    }
}

/// The type of TCP stream
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamType {
    /// Client -> Server
    Client,
    /// Server -> Client
    Server,
}

/// Reader for reading encrypted data stream from shadowsocks' tunnel
#[allow(clippy::large_enum_variant)]
pub enum DecryptedReader {
    None,
    #[cfg(feature = "aead-cipher")]
    Aead(AeadDecryptedReader),
    #[cfg(feature = "stream-cipher")]
    Stream(StreamDecryptedReader),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022DecryptedReader),
}

impl DecryptedReader {
    /// Create a new reader for reading encrypted data
    pub fn new(stream_ty: StreamType, method: CipherKind, key: &[u8]) -> Self {
        Self::with_user_manager(stream_ty, method, key, None)
    }

    /// Create a new reader for reading encrypted data
    pub fn with_user_manager(
        stream_ty: StreamType,
        method: CipherKind,
        key: &[u8],
        user_manager: Option<Arc<ServerUserManager>>,
    ) -> Self {
        if cfg!(not(feature = "aead-cipher-2022")) {
            let _ = stream_ty;
            let _ = user_manager;
        }

        match method.category() {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => Self::Stream(StreamDecryptedReader::new(method, key)),
            #[cfg(feature = "aead-cipher")]
            CipherCategory::Aead => Self::Aead(AeadDecryptedReader::new(method, key)),
            CipherCategory::None => {
                let _ = method;
                let _ = key;
                Self::None
            }
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => Self::Aead2022(Aead2022DecryptedReader::with_user_manager(
                stream_ty,
                method,
                key,
                user_manager,
            )),
        }
    }

    /// Attempt to read decrypted data from `stream`
    #[inline]
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
        match *self {
            #[cfg(feature = "stream-cipher")]
            Self::Stream(ref mut reader) => reader.poll_read_decrypted(cx, context, stream, buf).map_err(Into::into),
            #[cfg(feature = "aead-cipher")]
            Self::Aead(ref mut reader) => reader.poll_read_decrypted(cx, context, stream, buf).map_err(Into::into),
            Self::None => {
                let _ = context;
                Pin::new(stream).poll_read(cx, buf).map_err(Into::into)
            }
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref mut reader) => reader.poll_read_decrypted(cx, context, stream, buf).map_err(Into::into),
        }
    }

    /// Get received IV (Stream) or Salt (AEAD, AEAD2022)
    pub fn nonce(&self) -> Option<&[u8]> {
        match *self {
            #[cfg(feature = "stream-cipher")]
            Self::Stream(ref reader) => reader.iv(),
            #[cfg(feature = "aead-cipher")]
            Self::Aead(ref reader) => reader.salt(),
            Self::None => None,
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref reader) => reader.salt(),
        }
    }

    /// Get received request Salt (AEAD2022)
    pub fn request_nonce(&self) -> Option<&[u8]> {
        match *self {
            #[cfg(feature = "stream-cipher")]
            Self::Stream(..) => None,
            #[cfg(feature = "aead-cipher")]
            Self::Aead(..) => None,
            Self::None => None,
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref reader) => reader.request_salt(),
        }
    }

    /// Get authenticated user key (AEAD2022)
    pub fn user_key(&self) -> Option<&[u8]> {
        match *self {
            #[cfg(feature = "stream-cipher")]
            Self::Stream(..) => None,
            #[cfg(feature = "aead-cipher")]
            Self::Aead(..) => None,
            Self::None => None,
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref reader) => reader.user_key(),
        }
    }

    pub fn handshaked(&self) -> bool {
        match *self {
            #[cfg(feature = "stream-cipher")]
            Self::Stream(ref reader) => reader.handshaked(),
            #[cfg(feature = "aead-cipher")]
            Self::Aead(ref reader) => reader.handshaked(),
            Self::None => true,
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref reader) => reader.handshaked(),
        }
    }
}

/// Writer for writing encrypted data stream into shadowsocks' tunnel
#[allow(clippy::large_enum_variant)]
pub enum EncryptedWriter {
    None,
    #[cfg(feature = "aead-cipher")]
    Aead(AeadEncryptedWriter),
    #[cfg(feature = "stream-cipher")]
    Stream(StreamEncryptedWriter),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022EncryptedWriter),
}

impl EncryptedWriter {
    /// Create a new writer for writing encrypted data
    pub fn new(stream_ty: StreamType, method: CipherKind, key: &[u8], nonce: &[u8]) -> Self {
        if cfg!(not(feature = "aead-cipher-2022")) {
            let _ = stream_ty;
        }

        match method.category() {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => Self::Stream(StreamEncryptedWriter::new(method, key, nonce)),
            #[cfg(feature = "aead-cipher")]
            CipherCategory::Aead => Self::Aead(AeadEncryptedWriter::new(method, key, nonce)),
            CipherCategory::None => {
                let _ = key;
                let _ = nonce;
                Self::None
            }
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => Self::Aead2022(Aead2022EncryptedWriter::new(stream_ty, method, key, nonce)),
        }
    }

    /// Create a new writer for writing encrypted data
    pub fn with_identity(
        stream_ty: StreamType,
        method: CipherKind,
        key: &[u8],
        nonce: &[u8],
        identity_keys: &[Bytes],
    ) -> Self {
        if cfg!(not(feature = "aead-cipher-2022")) {
            let _ = stream_ty;
            let _ = identity_keys;
        }

        match method.category() {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => Self::Stream(StreamEncryptedWriter::new(method, key, nonce)),
            #[cfg(feature = "aead-cipher")]
            CipherCategory::Aead => Self::Aead(AeadEncryptedWriter::new(method, key, nonce)),
            CipherCategory::None => {
                let _ = key;
                let _ = nonce;
                Self::None
            }
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => Self::Aead2022(Aead2022EncryptedWriter::with_identity(
                stream_ty,
                method,
                key,
                nonce,
                identity_keys,
            )),
        }
    }

    /// Attempt to write encrypted data to `stream`
    #[inline]
    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut S,
        buf: &[u8],
    ) -> Poll<ProtocolResult<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        match *self {
            #[cfg(feature = "stream-cipher")]
            Self::Stream(ref mut writer) => writer.poll_write_encrypted(cx, stream, buf).map_err(Into::into),
            #[cfg(feature = "aead-cipher")]
            Self::Aead(ref mut writer) => writer.poll_write_encrypted(cx, stream, buf).map_err(Into::into),
            Self::None => Pin::new(stream).poll_write(cx, buf).map_err(Into::into),
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref mut writer) => writer.poll_write_encrypted(cx, stream, buf).map_err(Into::into),
        }
    }

    /// Get sent IV (Stream) or Salt (AEAD, AEAD2022)
    pub fn nonce(&self) -> &[u8] {
        match *self {
            #[cfg(feature = "stream-cipher")]
            Self::Stream(ref writer) => writer.iv(),
            #[cfg(feature = "aead-cipher")]
            Self::Aead(ref writer) => writer.salt(),
            Self::None => &[],
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref writer) => writer.salt(),
        }
    }

    /// Set request nonce (for server stream of AEAD2022)
    pub fn set_request_nonce(&mut self, request_nonce: Bytes) {
        match *self {
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref mut writer) => writer.set_request_salt(request_nonce),
            _ => {
                let _ = request_nonce;
                panic!("only AEAD-2022 cipher could send request salt");
            }
        }
    }

    /// Reset cipher with authenticated user key
    pub fn reset_cipher_with_key(&mut self, key: &[u8]) {
        match *self {
            #[cfg(feature = "aead-cipher-2022")]
            Self::Aead2022(ref mut writer) => writer.reset_cipher_with_key(key),
            _ => {
                let _ = key;
                panic!("only AEAD-2022 cipher could authenticate with multiple users");
            }
        }
    }
}

/// A bidirectional stream for read/write encrypted data in shadowsocks' tunnel
pub struct CryptoStream<S> {
    stream: S,
    dec: DecryptedReader,
    enc: EncryptedWriter,
    method: CipherKind,
    has_handshaked: bool,
}

impl<S> fmt::Debug for CryptoStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoStream")
            .field("method", &self.method)
            .field("has_handshaked", &self.has_handshaked)
            .finish()
    }
}

impl<S> CryptoStream<S> {
    /// Create a new CryptoStream with the underlying stream connection
    pub fn from_stream(context: &Context, stream: S, stream_ty: StreamType, method: CipherKind, key: &[u8]) -> Self {
        const EMPTY_IDENTITY: [Bytes; 0] = [];
        Self::from_stream_with_identity(context, stream, stream_ty, method, key, &EMPTY_IDENTITY, None)
    }

    /// Create a new CryptoStream with the underlying stream connection
    pub fn from_stream_with_identity(
        context: &Context,
        stream: S,
        stream_ty: StreamType,
        method: CipherKind,
        key: &[u8],
        identity_keys: &[Bytes],
        user_manager: Option<Arc<ServerUserManager>>,
    ) -> Self {
        let category = method.category();

        if category == CipherCategory::None {
            // Fast-path for none cipher
            return Self::new_none(stream, method);
        }

        let prev_len = match category {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => method.iv_len(),
            #[cfg(feature = "aead-cipher")]
            CipherCategory::Aead => method.salt_len(),
            CipherCategory::None => 0,
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => method.salt_len(),
        };

        let iv = match category {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => {
                let mut local_iv = vec![0u8; prev_len];
                context.generate_nonce(method, &mut local_iv, true);
                trace!("generated Stream cipher IV {:?}", ByteStr::new(&local_iv));
                local_iv
            }
            #[cfg(feature = "aead-cipher")]
            CipherCategory::Aead => {
                let mut local_salt = vec![0u8; prev_len];
                context.generate_nonce(method, &mut local_salt, true);
                trace!("generated AEAD cipher salt {:?}", ByteStr::new(&local_salt));
                local_salt
            }
            CipherCategory::None => {
                debug_assert_eq!(prev_len, 0);
                let _ = context;
                Vec::new()
            }
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => {
                // AEAD-2022 has a request-salt in respond header, so the generated salt doesn't need to be remembered.

                let mut local_salt = vec![0u8; prev_len];
                context.generate_nonce(method, &mut local_salt, false);
                trace!("generated AEAD cipher salt {:?}", ByteStr::new(&local_salt));
                local_salt
            }
        };

        Self {
            stream,
            dec: DecryptedReader::with_user_manager(stream_ty, method, key, user_manager),
            enc: EncryptedWriter::with_identity(stream_ty, method, key, &iv, identity_keys),
            method,
            has_handshaked: false,
        }
    }

    fn new_none(stream: S, method: CipherKind) -> Self {
        Self {
            stream,
            dec: DecryptedReader::None,
            enc: EncryptedWriter::None,
            method,
            has_handshaked: false,
        }
    }

    /// Return a reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Return a mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consume the CryptoStream and return the internal stream instance
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Get received IV (Stream) or Salt (AEAD, AEAD2022)
    #[inline]
    pub fn received_nonce(&self) -> Option<&[u8]> {
        self.dec.nonce()
    }

    /// Get sent IV (Stream) or Salt (AEAD, AEAD2022)
    #[inline]
    pub fn sent_nonce(&self) -> &[u8] {
        self.enc.nonce()
    }

    /// Received request salt from server (AEAD2022)
    #[inline]
    pub fn received_request_nonce(&self) -> Option<&[u8]> {
        self.dec.request_nonce()
    }

    /// Set request nonce (for server stream of AEAD2022)
    #[inline]
    pub fn set_request_nonce(&mut self, request_nonce: &[u8]) {
        self.enc.set_request_nonce(Bytes::copy_from_slice(request_nonce))
    }

    #[cfg(feature = "aead-cipher-2022")]
    pub(crate) fn set_request_nonce_with_received(&mut self) -> bool {
        match self.dec.nonce() {
            None => false,
            Some(nonce) => {
                self.enc.set_request_nonce(Bytes::copy_from_slice(nonce));
                true
            }
        }
    }

    /// Get remaining bytes in the current data chunk
    ///
    /// Returning (DataChunkCount, RemainingBytes)
    #[cfg(feature = "aead-cipher-2022")]
    pub(crate) fn current_data_chunk_remaining(&self) -> (u64, usize) {
        match self.dec {
            DecryptedReader::Aead2022(ref dec) => dec.current_data_chunk_remaining(),
            _ => {
                panic!("only AEAD-2022 protocol has data chunk counter");
            }
        }
    }
}

/// Cryptographic reader trait
pub trait CryptoRead {
    fn poll_read_decrypted(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        context: &Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<ProtocolResult<()>>;
}

/// Cryptographic writer trait
pub trait CryptoWrite {
    fn poll_write_encrypted(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<ProtocolResult<usize>>;
}

impl<S> CryptoStream<S> {
    /// Get encryption method
    pub fn method(&self) -> CipherKind {
        self.method
    }
}

impl<S> CryptoRead for CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Attempt to read decrypted data from `stream`
    #[inline]
    fn poll_read_decrypted(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        context: &Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<ProtocolResult<()>> {
        let Self {
            ref mut dec,
            ref mut enc,
            ref mut stream,
            ref mut has_handshaked,
            ..
        } = *self;
        ready!(dec.poll_read_decrypted(cx, context, stream, buf))?;

        if !*has_handshaked && dec.handshaked() {
            *has_handshaked = true;

            // Reset writer cipher with authenticated user key
            if let Some(user_key) = dec.user_key() {
                enc.reset_cipher_with_key(user_key);
            }
        }

        Ok(()).into()
    }
}

impl<S> CryptoWrite for CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Attempt to write encrypted data to `stream`
    #[inline]
    fn poll_write_encrypted(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<ProtocolResult<usize>> {
        let Self {
            ref mut enc,
            ref mut stream,
            ..
        } = *self;
        enc.poll_write_encrypted(cx, stream, buf)
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Polls `flush` on the underlying stream
    #[inline]
    pub fn poll_flush(&mut self, cx: &mut task::Context<'_>) -> Poll<ProtocolResult<()>> {
        Pin::new(&mut self.stream).poll_flush(cx).map_err(Into::into)
    }

    /// Polls `shutdown` on the underlying stream
    #[inline]
    pub fn poll_shutdown(&mut self, cx: &mut task::Context<'_>) -> Poll<ProtocolResult<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx).map_err(Into::into)
    }
}
