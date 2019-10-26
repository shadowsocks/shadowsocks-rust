//! IO facilities for TCP relay

use std::{
    io,
    marker::{PhantomData, Unpin},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use byte_string::ByteStr;
use log::trace;
use tokio::prelude::*;

use super::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};

use crate::{
    config::ServerConfig,
    crypto::{CipherCategory, CipherType},
    relay::utils::try_timeout,
};

enum CryptoContext {
    Aead(AeadDecryptedReader, AeadEncryptedWriter),
    Stream(StreamDecryptedReader, StreamEncryptedWriter),
}

pub struct CryptoStream<S> {
    stream: S,
    context: CryptoContext,
}

impl<S: Unpin> Unpin for CryptoStream<S> {}

impl<S> CryptoStream<S> {
    pub fn new(stream: S, t: CipherType, key: &[u8], enc_nonce: &[u8], dec_nonce: &[u8]) -> CryptoStream<S> {
        let context = match t.category() {
            CipherCategory::Aead => CryptoContext::Aead(
                AeadDecryptedReader::new(t, key, enc_nonce),
                AeadEncryptedWriter::new(t, key, dec_nonce),
            ),
            CipherCategory::Stream => CryptoContext::Stream(
                StreamDecryptedReader::new(t, key, enc_nonce),
                StreamEncryptedWriter::new(t, key, dec_nonce),
            ),
        };

        CryptoStream {
            stream: stream,
            context: context,
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn handshake(mut stream: S, svr_cfg: Arc<ServerConfig>) -> io::Result<CryptoStream<S>> {
        let timeout = svr_cfg.timeout();

        let enc_nonce = {
            // Encrypt data to remote server

            // Send initialize vector to remote and create encryptor

            let method = svr_cfg.method();
            let iv = match method.category() {
                CipherCategory::Stream => {
                    let local_iv = method.gen_init_vec();
                    trace!("Going to send initialize vector: {:?}", local_iv);
                    local_iv
                }
                CipherCategory::Aead => {
                    let local_salt = method.gen_salt();
                    trace!("Going to send salt: {:?}", local_salt);
                    local_salt
                }
            };

            // Send IV to remote
            try_timeout(stream.write_all(&iv), timeout).await?;

            iv
        };

        let dec_nonce = {
            // Decrypt data from remote server

            let method = svr_cfg.method();
            let prev_len = match method.category() {
                CipherCategory::Stream => method.iv_size(),
                CipherCategory::Aead => method.salt_size(),
            };

            // Read IV from remote
            let mut remote_iv = vec![0u8; prev_len];
            try_timeout(stream.read_exact(&mut remote_iv), timeout).await?;

            match svr_cfg.method().category() {
                CipherCategory::Stream => {
                    trace!("Got initialize vector {:?}", ByteStr::new(&remote_iv));
                }
                CipherCategory::Aead => {
                    trace!("Got salt {:?}", ByteStr::new(&remote_iv));
                }
            }

            remote_iv
        };

        Ok(CryptoStream::new(
            stream,
            svr_cfg.method(),
            svr_cfg.key(),
            &enc_nonce[..],
            &dec_nonce[..],
        ))
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn priv_poll_read(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let stream = unsafe { &mut *(&mut self.stream as *mut _) };
        match self.context {
            CryptoContext::Aead(ref mut r, _) => r.poll_read_decrypted(ctx, stream, buf),
            CryptoContext::Stream(ref mut r, _) => r.poll_read_decrypted(ctx, stream, buf),
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncWrite + Unpin,
{
    pub(crate) fn priv_poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream = unsafe { &mut *(&mut self.stream as *mut _) };
        match self.context {
            CryptoContext::Aead(_, ref mut w) => w.poll_write_encrypted(ctx, stream, buf),
            CryptoContext::Stream(_, ref mut w) => w.poll_write_encrypted(ctx, stream, buf),
        }
    }

    pub(crate) fn priv_poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.stream), ctx)
    }

    pub(crate) fn priv_poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), ctx)
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn split<'a>(&'a mut self) -> (CryptoStreamReadHalf<'a, S>, CryptoStreamWriteHalf<'a, S>) {
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
