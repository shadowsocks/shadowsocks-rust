//! IO facilities for TCP relay

use std::{
    io,
    marker::Unpin,
    pin::Pin,
    task::{self, Poll},
};

use byte_string::ByteStr;
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::{
    context::Context,
    crypto::{CipherCategory, CipherKind},
};

use super::aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter};
#[cfg(feature = "aead-cipher-2022")]
use super::aead_2022::{DecryptedReader as Aead2022DecryptedReader, EncryptedWriter as Aead2022EncryptedWriter};
#[cfg(feature = "stream-cipher")]
use super::stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter};

/// Reader for reading encrypted data stream from shadowsocks' tunnel
#[allow(clippy::large_enum_variant)]
pub enum DecryptedReader {
    None,
    Aead(AeadDecryptedReader),
    #[cfg(feature = "stream-cipher")]
    Stream(StreamDecryptedReader),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022DecryptedReader),
}

impl DecryptedReader {
    /// Create a new reader for reading encrypted data
    pub fn new(method: CipherKind, key: &[u8]) -> DecryptedReader {
        match method.category() {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => DecryptedReader::Stream(StreamDecryptedReader::new(method, key)),
            CipherCategory::Aead => DecryptedReader::Aead(AeadDecryptedReader::new(method, key)),
            CipherCategory::None => DecryptedReader::None,
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => DecryptedReader::Aead2022(Aead2022DecryptedReader::new(method, key)),
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
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        match *self {
            #[cfg(feature = "stream-cipher")]
            DecryptedReader::Stream(ref mut reader) => reader.poll_read_decrypted(cx, context, stream, buf),
            DecryptedReader::Aead(ref mut reader) => reader.poll_read_decrypted(cx, context, stream, buf),
            DecryptedReader::None => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "aead-cipher-2022")]
            DecryptedReader::Aead2022(ref mut reader) => reader.poll_read_decrypted(cx, context, stream, buf),
        }
    }

    /// Get received IV (Stream) or Salt (AEAD, AEAD2022)
    pub fn nonce(&self) -> Option<&[u8]> {
        match *self {
            #[cfg(feature = "stream-cipher")]
            DecryptedReader::Stream(ref reader) => reader.iv(),
            DecryptedReader::Aead(ref reader) => reader.salt(),
            DecryptedReader::None => None,
            #[cfg(feature = "aead-cipher-2022")]
            DecryptedReader::Aead2022(ref reader) => reader.salt(),
        }
    }
}

/// Writer for writing encrypted data stream into shadowsocks' tunnel
pub enum EncryptedWriter {
    None,
    Aead(AeadEncryptedWriter),
    #[cfg(feature = "stream-cipher")]
    Stream(StreamEncryptedWriter),
    #[cfg(feature = "aead-cipher-2022")]
    Aead2022(Aead2022EncryptedWriter),
}

impl EncryptedWriter {
    /// Create a new writer for writing encrypted data
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> EncryptedWriter {
        match method.category() {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => EncryptedWriter::Stream(StreamEncryptedWriter::new(method, key, nonce)),
            CipherCategory::Aead => EncryptedWriter::Aead(AeadEncryptedWriter::new(method, key, nonce)),
            CipherCategory::None => EncryptedWriter::None,
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => EncryptedWriter::Aead2022(Aead2022EncryptedWriter::new(method, key, nonce)),
        }
    }

    /// Attempt to write encrypted data to `stream`
    #[inline]
    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut S,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        match *self {
            #[cfg(feature = "stream-cipher")]
            EncryptedWriter::Stream(ref mut writer) => writer.poll_write_encrypted(cx, stream, buf),
            EncryptedWriter::Aead(ref mut writer) => writer.poll_write_encrypted(cx, stream, buf),
            EncryptedWriter::None => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "aead-cipher-2022")]
            EncryptedWriter::Aead2022(ref mut writer) => writer.poll_write_encrypted(cx, stream, buf),
        }
    }

    /// Get sent IV (Stream) or Salt (AEAD, AEAD2022)
    pub fn nonce(&self) -> &[u8] {
        match *self {
            #[cfg(feature = "stream-cipher")]
            EncryptedWriter::Stream(ref writer) => writer.iv(),
            EncryptedWriter::Aead(ref writer) => writer.salt(),
            EncryptedWriter::None => &[],
            #[cfg(feature = "aead-cipher-2022")]
            EncryptedWriter::Aead2022(ref writer) => writer.salt(),
        }
    }
}

/// A bidirectional stream for read/write encrypted data in shadowsocks' tunnel
pub struct CryptoStream<S> {
    stream: S,
    dec: DecryptedReader,
    enc: EncryptedWriter,
    method: CipherKind,
}

impl<S> CryptoStream<S> {
    /// Create a new CryptoStream with the underlying stream connection
    pub fn from_stream(context: &Context, stream: S, method: CipherKind, key: &[u8]) -> CryptoStream<S> {
        let category = method.category();

        if category == CipherCategory::None {
            // Fast-path for none cipher
            return CryptoStream::<S>::new_none(stream, method);
        }

        let prev_len = match category {
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => method.iv_len(),
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
            CipherCategory::Aead => {
                let mut local_salt = vec![0u8; prev_len];
                context.generate_nonce(method, &mut local_salt, true);
                trace!("generated AEAD cipher salt {:?}", ByteStr::new(&local_salt));
                local_salt
            }
            CipherCategory::None => Vec::new(),
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => {
                let mut local_salt = vec![0u8; prev_len];
                context.generate_nonce(method, &mut local_salt, true);
                trace!("generated AEAD cipher salt {:?}", ByteStr::new(&local_salt));
                local_salt
            }
        };

        CryptoStream {
            stream,
            dec: DecryptedReader::new(method, key),
            enc: EncryptedWriter::new(method, key, &iv),
            method,
        }
    }

    fn new_none(stream: S, method: CipherKind) -> CryptoStream<S> {
        CryptoStream {
            stream,
            dec: DecryptedReader::None,
            enc: EncryptedWriter::None,
            method,
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
    pub fn received_nonce(&self) -> Option<&[u8]> {
        self.dec.nonce()
    }

    /// Get sent IV (Stream) or Salt (AEAD, AEAD2022)
    pub fn sent_nonce(&self) -> &[u8] {
        self.enc.nonce()
    }
}

/// Cryptographic reader trait
pub trait CryptoRead {
    fn poll_read_decrypted(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        context: &Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;
}

/// Cryptographic writer trait
pub trait CryptoWrite {
    fn poll_write_encrypted(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;
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
    ) -> Poll<io::Result<()>> {
        let CryptoStream {
            ref mut dec,
            ref mut stream,
            ..
        } = *self;
        dec.poll_read_decrypted(cx, context, stream, buf)
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
    ) -> Poll<io::Result<usize>> {
        let CryptoStream {
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
    pub fn poll_flush(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    /// Polls `shutdown` on the underlying stream
    #[inline]
    pub fn poll_shutdown(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn into_split(self) -> (CryptoStreamReadHalf<S>, CryptoStreamWriteHalf<S>) {
        let (reader, writer) = tokio::io::split(self.stream);

        (
            CryptoStreamReadHalf {
                reader,
                dec: self.dec,
                method: self.method,
            },
            CryptoStreamWriteHalf {
                writer,
                enc: self.enc,
                method: self.method,
            },
        )
    }
}

pub struct CryptoStreamReadHalf<S> {
    reader: ReadHalf<S>,
    dec: DecryptedReader,
    method: CipherKind,
}

impl<S> CryptoStreamReadHalf<S> {
    /// Get encryption method
    pub fn method(&self) -> CipherKind {
        self.method
    }
}

impl<S> CryptoStreamReadHalf<S>
where
    S: AsyncRead + Unpin,
{
    /// Get received IV (Stream) or Salt (AEAD, AEAD2022)
    pub fn nonce(&self) -> Option<&[u8]> {
        self.dec.nonce()
    }
}

impl<S> CryptoRead for CryptoStreamReadHalf<S>
where
    S: AsyncRead + Unpin,
{
    /// Attempt to read decrypted data from `stream`
    #[inline]
    fn poll_read_decrypted(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        context: &Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let CryptoStreamReadHalf {
            ref mut dec,
            ref mut reader,
            ..
        } = *self;
        dec.poll_read_decrypted(cx, context, reader, buf)
    }
}

pub struct CryptoStreamWriteHalf<S> {
    writer: WriteHalf<S>,
    enc: EncryptedWriter,
    method: CipherKind,
}

impl<S> CryptoStreamWriteHalf<S> {
    /// Get encryption method
    pub fn method(&self) -> CipherKind {
        self.method
    }

    /// Get sent IV (Stream) or Salt (AEAD, AEAD2022)
    pub fn sent_nonce(&self) -> &[u8] {
        self.enc.nonce()
    }
}

impl<S> CryptoWrite for CryptoStreamWriteHalf<S>
where
    S: AsyncWrite + Unpin,
{
    /// Attempt to write encrypted data to `stream`
    #[inline]
    fn poll_write_encrypted(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let CryptoStreamWriteHalf {
            ref mut enc,
            ref mut writer,
            ..
        } = *self;
        enc.poll_write_encrypted(cx, writer, buf)
    }
}

impl<S> CryptoStreamWriteHalf<S>
where
    S: AsyncWrite + Unpin,
{
    /// Polls `flush` on the underlying stream
    #[inline]
    pub fn poll_flush(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    /// Polls `shutdown` on the underlying stream
    #[inline]
    pub fn poll_shutdown(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
