//! IO facilities for TCP relay

use std::{
    io,
    marker::{PhantomData, Unpin},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use byte_string::ByteStr;
use bytes::Bytes;
use futures::ready;
use log::trace;
use tokio::prelude::*;

use super::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};

use crate::{config::ServerConfig, crypto::CipherCategory};

enum DecryptedReader {
    Aead(AeadDecryptedReader),
    Stream(StreamDecryptedReader),
}

enum EncryptedWriter {
    Aead(AeadEncryptedWriter),
    Stream(StreamEncryptedWriter),
}

enum ReadStatus {
    WaitIv(Vec<u8>, usize),
    Established,
}

enum WriteStatus {
    SendIv(Bytes, usize),
    Established,
}

pub struct CryptoStream<S> {
    stream: S,
    dec: Option<DecryptedReader>,
    enc: Option<EncryptedWriter>,
    svr_cfg: Arc<ServerConfig>,
    read_status: ReadStatus,
    write_status: WriteStatus,
}

impl<S: Unpin> Unpin for CryptoStream<S> {}

impl<S> CryptoStream<S> {
    pub fn new(stream: S, svr_cfg: Arc<ServerConfig>) -> CryptoStream<S> {
        let method = svr_cfg.method();
        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_size(),
            CipherCategory::Aead => method.salt_size(),
        };

        let local_iv = match method.category() {
            CipherCategory::Stream => {
                let local_iv = method.gen_init_vec();
                trace!("Generated Stream cipher IV {:?}", local_iv);
                local_iv
            }
            CipherCategory::Aead => {
                let local_salt = method.gen_salt();
                trace!("Generated AEAD cipher salt {:?}", local_salt);
                local_salt
            }
        };

        CryptoStream {
            stream,
            dec: None,
            enc: None,
            svr_cfg,
            read_status: ReadStatus::WaitIv(vec![0u8; prev_len], 0usize),
            write_status: WriteStatus::SendIv(local_iv, 0usize),
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref mut buf, ref mut pos) = self.read_status {
            while *pos < buf.len() {
                let n = ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf[*pos..]))?;
                if n == 0 {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof");
                    return Poll::Ready(Err(err));
                }
                *pos += n;
            }

            let method = self.svr_cfg.method();
            let dec = match method.category() {
                CipherCategory::Stream => {
                    trace!("Got Stream cipher IV {:?}", ByteStr::new(&buf));
                    DecryptedReader::Stream(StreamDecryptedReader::new(method, self.svr_cfg.key(), &buf))
                }
                CipherCategory::Aead => {
                    trace!("Got AEAD cipher salt {:?}", ByteStr::new(&buf));
                    DecryptedReader::Aead(AeadDecryptedReader::new(method, self.svr_cfg.key(), &buf))
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
    fn poll_write_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let WriteStatus::SendIv(ref iv, ref mut pos) = self.write_status {
            while *pos < iv.len() {
                let n = ready!(Pin::new(&mut self.stream).poll_write(cx, &iv[*pos..]))?;
                if n == 0 {
                    let err = io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof");
                    return Poll::Ready(Err(err));
                }
                *pos += n;
            }

            let method = self.svr_cfg.method();
            let enc = match method.category() {
                CipherCategory::Stream => {
                    trace!("Sent Stream cipher IV {:?}", ByteStr::new(&iv));
                    EncryptedWriter::Stream(StreamEncryptedWriter::new(method, self.svr_cfg.key(), &iv))
                }
                CipherCategory::Aead => {
                    trace!("Sent AEAD cipher salt {:?}", ByteStr::new(&iv));
                    EncryptedWriter::Aead(AeadEncryptedWriter::new(method, self.svr_cfg.key(), &iv))
                }
            };

            self.enc = Some(enc);
            self.write_status = WriteStatus::Established;
        }

        Poll::Ready(Ok(()))
    }

    fn priv_poll_write(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        ready!(self.poll_write_handshake(ctx))?;

        let stream = unsafe { &mut *(&mut self.stream as *mut _) };
        match *self.enc.as_mut().unwrap() {
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
