//! Relay for TCP implementation

use std::{
    io::{self, BufRead, Read, Write},
    iter::Iterator,
    marker::Unpin,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::SharedContext,
    crypto::CipherCategory,
    relay::{dns_resolver::resolve, socks5::Address, utils::try_timeout},
};

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use futures::{future::FusedFuture, select};
use log::{error, trace};
use tokio::{
    net::{
        tcp::split::{TcpStreamReadHalf, TcpStreamWriteHalf},
        TcpStream,
    },
    prelude::*,
};

pub use self::crypto_io::{DecryptedRead, EncryptedWrite};

use self::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};

mod aead;
pub mod client;
mod context;
mod crypto_io;
pub mod local;
mod monitor;
pub mod server;
mod socks5_local;
mod stream;
mod utils;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

/// `ReadHalf `of `TcpStream` with decryption
pub enum DecryptedHalf<R> {
    Stream(StreamDecryptedReader<R>),
    Aead(AeadDecryptedReader<R>),
}

macro_rules! ref_half_do {
    ($self:expr,$t:ident,$m:ident$(,$p:expr)*) => {
        match *$self {
            $t::Stream(ref d) => d.$m($($p),*),
            $t::Aead(ref d) => d.$m($($p),*),
        }
    }
}

macro_rules! mut_half_do {
    ($self:expr,$t:ident,$m:ident$(,$p:expr)*) => {
        match *$self {
            $t::Stream(ref mut d) => d.$m($($p),*),
            $t::Aead(ref mut d) => d.$m($($p),*),
        }
    }
}

macro_rules! mut_pin_half_do {
    ($self:expr,$t:ident,$m:ident$(,$p:expr)*) => {
        match *$self {
            $t::Stream(ref mut d) => Pin::new(&mut d).$m($($p),*),
            $t::Aead(ref mut d) => Pin::new(&mut d).$m($($p),*),
        }
    }
}

impl<R: Unpin> Unpin for DecryptedHalf<R> {}

impl<R> DecryptedRead for DecryptedHalf<R>
where
    R: AsyncRead + Unpin,
{
    fn buffer_size(&self, data: &[u8]) -> usize {
        ref_half_do!(self, DecryptedHalf, buffer_size, data)
    }
}

impl<R> AsyncRead for DecryptedHalf<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        mut_pin_half_do!(self, DecryptedHalf, poll_read, cx, buf)
    }
}

impl<R> From<StreamDecryptedReader<R>> for DecryptedHalf<R> {
    fn from(r: StreamDecryptedReader<R>) -> DecryptedHalf<R> {
        DecryptedHalf::Stream(r)
    }
}

impl<R> From<AeadDecryptedReader<R>> for DecryptedHalf<R> {
    fn from(r: AeadDecryptedReader<R>) -> DecryptedHalf<R> {
        DecryptedHalf::Aead(r)
    }
}

/// `WriteHalf` of `TcpStream` with encryption
pub enum EncryptedHalf<W> {
    Stream(StreamEncryptedWriter<W>),
    Aead(AeadEncryptedWriter<W>),
}

impl<W> AsyncWrite for EncryptedHalf<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        mut_pin_half_do!(self, EncryptedHalf, poll_write, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        mut_pin_half_do!(self, EncryptedHalf, poll_flush, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        mut_pin_half_do!(self, EncryptedHalf, poll_shutdown, cx)
    }
}

impl<W> EncryptedWrite for EncryptedHalf<W>
where
    W: AsyncWrite + Unpin,
{
    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        mut_half_do!(self, EncryptedHalf, encrypt, data, buf)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        ref_half_do!(self, EncryptedHalf, buffer_size, data)
    }
}

impl<W> From<StreamEncryptedWriter<W>> for EncryptedHalf<W> {
    fn from(d: StreamEncryptedWriter<W>) -> EncryptedHalf<W> {
        EncryptedHalf::Stream(d)
    }
}

impl<W> From<AeadEncryptedWriter<W>> for EncryptedHalf<W> {
    fn from(d: AeadEncryptedWriter<W>) -> EncryptedHalf<W> {
        EncryptedHalf::Aead(d)
    }
}

/// Connect to proxy server with `ServerConfig`
async fn connect_proxy_server(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> io::Result<TcpStream> {
    let timeout = svr_cfg.timeout();

    let svr_addr = match context.config().config_type {
        ConfigType::Server => svr_cfg.addr(),
        ConfigType::Local => svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr()),
    };

    trace!("Connecting to proxy {:?}, timeout: {:?}", svr_addr, timeout);
    match svr_addr {
        ServerAddr::SocketAddr(ref addr) => {
            let stream = try_timeout(TcpStream::connect(addr), timeout).await?;
            Ok(stream)
        }
        ServerAddr::DomainName(ref domain, port) => {
            let vec_ipaddr = try_timeout(resolve(context, &domain[..], *port, false), timeout).await?;

            assert!(!vec_ipaddr.is_empty());

            let last_err: Option<io::Error> = None;
            for addr in &vec_ipaddr {
                match try_timeout(TcpStream::connect(addr), timeout).await {
                    Ok(s) => return Ok(s),
                    Err(e) => {
                        error!(
                            "Failed to connect {}:{}, resolved address {}, try another (err: {})",
                            domain, port, addr, e
                        );
                        last_err = Some(e);
                    }
                }
            }

            let err = last_err.unwrap();
            error!(
                "Failed to connect {}:{}, tried all addresses but still failed (last err: {})",
                domain, port, err
            );
            Err(err)
        }
    }
}

/// Handshake logic for ShadowSocks Client
pub async fn proxy_server_handshake(
    remote_stream: TcpStream,
    svr_cfg: Arc<ServerConfig>,
    relay_addr: &Address,
) -> io::Result<(DecryptedHalf<TcpStreamReadHalf>, EncryptedHalf<TcpStreamWriteHalf>)> {
    let (rr, rw) = remote_stream.split();
    let (r, w) = proxy_handshake(rr, rw, svr_cfg).await?;

    trace!("Got encrypt stream and going to send addr: {:?}", relay_addr);

    // Send relay address to remote
    let mut addr_buf = BytesMut::with_capacity(relay_addr.serialized_len());
    relay_addr.write_to_buf(&mut addr_buf);
    try_timeout(w.encrypted_write_all(&addr_buf), svr_cfg.timeout()).await?;

    Ok((r, w))
}

/// ShadowSocks Client-Server handshake protocol
/// Exchange cipher IV and creates stream wrapper
pub async fn proxy_handshake<R, W>(
    r: R,
    w: W,
    svr_cfg: Arc<ServerConfig>,
) -> io::Result<(DecryptedHalf<R>, EncryptedHalf<W>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let timeout = svr_cfg.timeout();

    let enc = {
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
        try_timeout(w.write_all(&iv), timeout).await?;

        match svr_cfg.method().category() {
            CipherCategory::Stream => {
                let wtr = StreamEncryptedWriter::new(w, svr_cfg.method(), svr_cfg.key(), &iv);
                From::from(wtr)
            }
            CipherCategory::Aead => {
                let wtr = AeadEncryptedWriter::new(w, svr_cfg.method(), svr_cfg.key(), &iv);
                From::from(wtr)
            }
        }
    };

    let dec = {
        // Decrypt data from remote server

        let method = svr_cfg.method();
        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_size(),
            CipherCategory::Aead => method.salt_size(),
        };

        // Read IV from remote
        let mut remote_iv = vec![0u8; prev_len];
        try_timeout(r.read_exact(&mut remote_iv), timeout).await?;

        match svr_cfg.method().category() {
            CipherCategory::Stream => {
                trace!("Got initialize vector {:?}", ByteStr::new(&remote_iv));
                let decrypt_stream = StreamDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                From::from(decrypt_stream)
            }
            CipherCategory::Aead => {
                trace!("Got salt {:?}", ByteStr::new(&remote_iv));
                let dr = AeadDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                From::from(dr)
            }
        }
    };

    Ok((dec, enc))
}

/// Establish tunnel between server and client
// pub fn tunnel<CF, CFI, SF, SFI>(addr: Address, c2s: CF, s2c: SF) -> impl Future<Item = (), Error = io::Error> + Send
pub async fn tunnel<CF, CFI, SF, SFI>(c2s: CF, s2c: SF) -> io::Result<()>
where
    CF: Future<Output = io::Result<CFI>> + Unpin + FusedFuture,
    SF: Future<Output = io::Result<SFI>> + Unpin + FusedFuture,
{
    select! {
        r1 = c2s => r1.map(|_| ()),
        r2 = s2c => r2.map(|_| ()),
    }

    // let addr = Arc::new(addr);

    // let cloned_addr = addr.clone();
    // let c2s = c2s.then(move |res| {
    //     match res {
    //         Ok(..) => {
    //             // Continue reading response from remote server
    //             trace!("Relay {} client -> server is finished", cloned_addr);

    //             Ok(TunnelDirection::Client2Server)
    //         }
    //         Err(err) => {
    //             error!("Relay {} client -> server aborted: {}", cloned_addr, err);
    //             Err(err)
    //         }
    //     }
    // });

    // let cloned_addr = addr.clone();
    // let s2c = s2c.then(move |res| match res {
    //     Ok(..) => {
    //         trace!("Relay {} client <- server is finished", cloned_addr);

    //         Ok(TunnelDirection::Server2Client)
    //     }
    //     Err(err) => {
    //         error!("Relay {} client <- server aborted: {}", cloned_addr, err);
    //         Err(err)
    //     }
    // });

    // c2s.select(s2c)
    //     .and_then(move |(dir, _)| {
    //         match dir {
    //             TunnelDirection::Server2Client => trace!("Relay {} client <- server is closed, abort connection", addr),
    //             TunnelDirection::Client2Server => trace!("Relay {} server -> client is closed, abort connection", addr),
    //         }

    //         Ok(())
    //     })
    //     .map_err(|(err, _)| err)
}

pub async fn ignore_until_end<R>(r: &mut R) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; BUFFER_SIZE];
    let mut amt = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        amt += n as u64;
    }
    Ok(amt)
}
