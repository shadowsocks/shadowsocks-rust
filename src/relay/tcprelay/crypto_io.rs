//! IO facilities for TCP relay

use std::{
    io,
    marker::{PhantomData, Unpin},
    pin::Pin,
    task::{Context, Poll},
};

use byte_string::ByteStr;
use bytes::Bytes;
use futures::ready;
use log::{error, trace};
use tokio::prelude::*;

use crate::{
    config::ServerConfig,
    context::{self, SharedServerState},
    crypto::{CipherCategory, CipherType},
};

use super::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};

enum DecryptedReader {
    Aead(AeadDecryptedReader),
    Stream(StreamDecryptedReader),
}

enum EncryptedWriter {
    Aead(AeadEncryptedWriter),
    Stream(StreamEncryptedWriter),
}

/// Steps for initializing a DecryptedReader
enum ReadStatus {
    /// Waiting for initializing vector (or nonce for AEAD ciphers)
    ///
    /// (context, Buffer, already_read_bytes, method, key)
    WaitIv(SharedServerState, Vec<u8>, usize, CipherType, Bytes),

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
    pub fn new(context: &context::Context, stream: S, svr_cfg: &ServerConfig) -> CryptoStream<S> {
        let method = svr_cfg.method();
        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_size(),
            CipherCategory::Aead => method.salt_size(),
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
                trace!("Generated Stream cipher IV {:?}", local_iv);
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
                trace!("Generated AEAD cipher salt {:?}", local_salt);
                local_salt
            }
        };

        let method = svr_cfg.method();
        let enc = match method.category() {
            CipherCategory::Stream => EncryptedWriter::Stream(StreamEncryptedWriter::new(method, svr_cfg.key(), iv)),
            CipherCategory::Aead => EncryptedWriter::Aead(AeadEncryptedWriter::new(method, svr_cfg.key(), iv)),
        };

        CryptoStream {
            stream,
            dec: None,
            enc,
            read_status: ReadStatus::WaitIv(
                context.clone_server_state(),
                vec![0u8; prev_len],
                0usize,
                method,
                svr_cfg.clone_key(),
            ),
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref ctx, ref mut buf, ref mut pos, method, ref key) = self.read_status {
            while *pos < buf.len() {
                let n = ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf[*pos..]))?;
                if n == 0 {
                    use std::io::ErrorKind;
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
                *pos += n;
            }

            // Got iv/salt, check if it is repeated
            if ctx.check_nonce_and_set(buf) {
                use std::io::{Error, ErrorKind};

                error!("Detected repeated iv/salt {:?}", ByteStr::new(buf));

                let err = Error::new(ErrorKind::Other, "detected repeated iv/salt");
                return Poll::Ready(Err(err));
            }

            let dec = match method.category() {
                CipherCategory::Stream => {
                    trace!("Got Stream cipher IV {:?}", ByteStr::new(&buf));
                    DecryptedReader::Stream(StreamDecryptedReader::new(method, key, &buf))
                }
                CipherCategory::Aead => {
                    trace!("Got AEAD cipher salt {:?}", ByteStr::new(&buf));
                    DecryptedReader::Aead(AeadDecryptedReader::new(method, key, &buf))
                }
            };

            self.dec = Some(dec);
            self.read_status = ReadStatus::Established;
        }

        Poll::Ready(Ok(()))
    }

    fn priv_poll_read(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        ready!(self.poll_read_handshake(ctx))?;

        let stream = unsafe { &mut *(&mut self.stream as *mut _) };
        match *self.dec.as_mut().unwrap() {
            DecryptedReader::Aead(ref mut r) => r.poll_read_decrypted(ctx, stream, buf),
            DecryptedReader::Stream(ref mut r) => r.poll_read_decrypted(ctx, stream, buf),
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn priv_poll_write(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let stream = unsafe { &mut *(&mut self.stream as *mut _) };
        match self.enc {
            EncryptedWriter::Aead(ref mut w) => w.poll_write_encrypted(ctx, stream, buf),
            EncryptedWriter::Stream(ref mut w) => w.poll_write_encrypted(ctx, stream, buf),
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
    pub fn split(&mut self) -> (CryptoStreamReadHalf<'_, S>, CryptoStreamWriteHalf<'_, S>) {
        let p = self as *mut _;
        (
            CryptoStreamReadHalf(p, PhantomData),
            CryptoStreamWriteHalf(p, PhantomData),
        )
    }
}

impl<S> AsyncRead for CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
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

pub struct CryptoStreamReadHalf<'a, S: 'a>(*mut CryptoStream<S>, PhantomData<&'a S>);

unsafe impl<'a, S: Send + 'a> Send for CryptoStreamReadHalf<'a, S> {}

impl<'a, S: AsyncRead + Unpin + 'a> AsyncRead for CryptoStreamReadHalf<'a, S> {
    fn poll_read(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let stream = unsafe { &mut *self.0 };
        Pin::new(stream).priv_poll_read(ctx, buf)
    }
}

pub struct CryptoStreamWriteHalf<'a, S: 'a>(*mut CryptoStream<S>, PhantomData<&'a S>);

unsafe impl<'a, S: Send + 'a> Send for CryptoStreamWriteHalf<'a, S> {}

impl<'a, S: AsyncWrite + Unpin + 'a> AsyncWrite for CryptoStreamWriteHalf<'a, S> {
    fn poll_write(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let stream = unsafe { &mut *self.0 };
        Pin::new(stream).priv_poll_write(ctx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = unsafe { &mut *self.0 };
        Pin::new(stream).priv_poll_flush(ctx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = unsafe { &mut *self.0 };
        Pin::new(stream).priv_poll_shutdown(ctx)
    }
}
