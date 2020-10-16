//! IO facilities for TCP relay

use std::{
    io,
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
};

use byte_string::ByteStr;
use bytes::{
    buf::ext::{BufMutExt, Limit},
    BufMut,
    Bytes,
    BytesMut,
};
use futures::ready;
use log::{debug, trace};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    crypto::{CipherCategory, CipherType},
};

use super::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};

enum DecryptedReader {
    None,
    Aead(AeadDecryptedReader),
    Stream(StreamDecryptedReader),
}

enum EncryptedWriter {
    None,
    Aead(AeadEncryptedWriter),
    Stream(StreamEncryptedWriter),
}

/// Steps for initializing a DecryptedReader
enum ReadStatus {
    /// Waiting for initializing vector (or nonce for AEAD ciphers)
    ///
    /// (context, Buffer, already_read_bytes, method, key)
    WaitIv(SharedContext, Limit<BytesMut>, CipherType, Bytes),

    /// Connection is established, DecryptedReader is initialized
    Established,
}

/// A bidirectional stream for communicating with ShadowSocks' server
pub struct CryptoStream<S> {
    stream: S,
    dec: Option<DecryptedReader>,
    enc: EncryptedWriter,
    read_status: ReadStatus,
}

impl<S: Unpin> Unpin for CryptoStream<S> {}

impl<S> CryptoStream<S> {
    /// Create a new CryptoStream with the underlying stream connection
    pub fn new(context: SharedContext, stream: S, svr_cfg: &ServerConfig) -> CryptoStream<S> {
        let method = svr_cfg.method();
        if method.category() == CipherCategory::None {
            return CryptoStream::<S>::new_none(stream);
        }

        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_size(),
            CipherCategory::Aead => method.salt_size(),
            CipherCategory::None => 0,
        };

        let iv = match method.category() {
            CipherCategory::Stream => {
                let local_iv = loop {
                    let iv = method.gen_init_vec();
                    if context.check_nonce_and_set(&iv) {
                        // IV exist, generate another one
                        continue;
                    }
                    break iv;
                };
                trace!("generated Stream cipher IV {:?}", local_iv);
                local_iv
            }
            CipherCategory::Aead => {
                let local_salt = loop {
                    let salt = method.gen_salt();
                    if context.check_nonce_and_set(&salt) {
                        // Salt exist, generate another one
                        continue;
                    }
                    break salt;
                };
                trace!("generated AEAD cipher salt {:?}", local_salt);
                local_salt
            }
            CipherCategory::None => Bytes::new(),
        };

        let method = svr_cfg.method();
        let enc = match method.category() {
            CipherCategory::Stream => EncryptedWriter::Stream(StreamEncryptedWriter::new(method, svr_cfg.key(), &iv)),
            CipherCategory::Aead => EncryptedWriter::Aead(AeadEncryptedWriter::new(method, svr_cfg.key(), &iv)),
            CipherCategory::None => EncryptedWriter::None,
        };

        CryptoStream {
            stream,
            dec: None,
            enc,
            read_status: ReadStatus::WaitIv(
                context,
                BytesMut::with_capacity(prev_len).limit(prev_len),
                method,
                svr_cfg.clone_key(),
            ),
        }
    }

    fn new_none(stream: S) -> CryptoStream<S> {
        CryptoStream {
            stream,
            dec: Some(DecryptedReader::None),
            enc: EncryptedWriter::None,
            read_status: ReadStatus::Established,
        }
    }

    /// Return a reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Consume the CryptoStream and return the internal stream instance
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref ctx, ref mut buf, method, ref key) = self.read_status {
            while buf.has_remaining_mut() {
                let mut buffer = ReadBuf::uninit(buf.bytes_mut());
                ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buffer))?;
                let n = buffer.filled().len();
                unsafe {
                    buf.advance_mut(n);
                }
                if n == 0 {
                    use std::io::ErrorKind;
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
            }

            let nonce = buf.get_ref();

            // Got iv/salt, check if it is repeated
            if ctx.check_nonce_and_set(nonce) {
                use std::io::{Error, ErrorKind};

                debug!("detected repeated iv/salt {:?}", ByteStr::new(nonce));

                let err = Error::new(ErrorKind::Other, "detected repeated iv/salt");
                return Poll::Ready(Err(err));
            }

            let dec = match method.category() {
                CipherCategory::Stream => {
                    trace!("got Stream cipher IV {:?}", ByteStr::new(nonce));
                    DecryptedReader::Stream(StreamDecryptedReader::new(method, key, nonce))
                }
                CipherCategory::Aead => {
                    trace!("got AEAD cipher salt {:?}", ByteStr::new(nonce));
                    DecryptedReader::Aead(AeadDecryptedReader::new(method, key, nonce))
                }
                CipherCategory::None => DecryptedReader::None,
            };

            self.dec = Some(dec);
            self.read_status = ReadStatus::Established;
        }

        Poll::Ready(Ok(()))
    }

    fn priv_poll_read(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_read_handshake(ctx))?;

        match *this.dec.as_mut().unwrap() {
            DecryptedReader::None => Pin::new(&mut this.stream).poll_read(ctx, buf),
            DecryptedReader::Aead(ref mut r) => r.poll_read_decrypted(ctx, &mut this.stream, buf),
            DecryptedReader::Stream(ref mut r) => r.poll_read_decrypted(ctx, &mut this.stream, buf),
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn priv_poll_write(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.enc {
            EncryptedWriter::None => Pin::new(&mut this.stream).poll_write(ctx, buf),
            EncryptedWriter::Aead(ref mut w) => w.poll_write_encrypted(ctx, &mut this.stream, buf),
            EncryptedWriter::Stream(ref mut w) => w.poll_write_encrypted(ctx, &mut this.stream, buf),
        }
    }

    fn priv_poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.stream), ctx)
    }

    fn priv_poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), ctx)
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Split connection into reader and writer
    ///
    /// The two halfs share the same `CryptoStream<S>`
    pub fn split(self) -> (ReadHalf<CryptoStream<S>>, WriteHalf<CryptoStream<S>>) {
        use tokio::io::split;
        split(self)
    }
}

impl<S> AsyncRead for CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_read(ctx, buf)
    }
}

impl<S> AsyncWrite for CryptoStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.priv_poll_write(ctx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_flush(ctx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_shutdown(ctx)
    }
}
