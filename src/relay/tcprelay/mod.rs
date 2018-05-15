//! Relay for TCP implementation

use std::io::{self, BufRead, Read};
use std::iter::{IntoIterator, Iterator};
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use config::{Config, ServerAddr, ServerConfig};
use crypto::CipherCategory;
use relay::boxed_future;
use relay::dns_resolver::resolve;
use relay::socks5::Address;

use tokio::net::{ConnectFuture, TcpStream};
use tokio_io::io::{read_exact, write_all};
use tokio_io::io::{ReadHalf, WriteHalf};
use tokio_io::{AsyncRead, IoFuture};

use futures::{self, Async, Future, Poll};

use bytes::{BufMut, BytesMut};

use byte_string::ByteStr;

pub use self::crypto_io::{DecryptedRead, EncryptedWrite};

use self::aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter};
use self::stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter};

mod aead;
pub mod client;
mod crypto_io;
pub mod local;
pub mod server;
mod socks5_local;
mod stream;
mod utils;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

/// Directions in the tunnel
#[derive(Debug, Copy, Clone)]
pub enum TunnelDirection {
    /// Client -> Server
    Client2Server,
    /// Client <- Server
    Server2Client,
}

type TcpReadHalf = ReadHalf<TcpStream>;
type TcpWriteHalf = WriteHalf<TcpStream>;

/// `ReadHalf `of `TcpStream` with decryption
pub enum DecryptedHalf {
    Stream(StreamDecryptedReader<TcpReadHalf>),
    Aead(AeadDecryptedReader<TcpReadHalf>),
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
            $t::Stream(ref mut  d) => d.$m($($p),*),
            $t::Aead(ref mut d) => d.$m($($p),*),
        }
    }
}

impl Read for DecryptedHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        mut_half_do!(self, DecryptedHalf, read, buf)
    }
}

impl DecryptedRead for DecryptedHalf {
    fn buffer_size(&self, data: &[u8]) -> usize {
        ref_half_do!(self, DecryptedHalf, buffer_size, data)
    }
}

impl AsyncRead for DecryptedHalf {}

impl BufRead for DecryptedHalf {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        mut_half_do!(self, DecryptedHalf, fill_buf)
    }

    fn consume(&mut self, amt: usize) {
        mut_half_do!(self, DecryptedHalf, consume, amt)
    }
}

impl From<StreamDecryptedReader<TcpReadHalf>> for DecryptedHalf {
    fn from(r: StreamDecryptedReader<TcpReadHalf>) -> DecryptedHalf {
        DecryptedHalf::Stream(r)
    }
}

impl From<AeadDecryptedReader<TcpReadHalf>> for DecryptedHalf {
    fn from(r: AeadDecryptedReader<TcpReadHalf>) -> DecryptedHalf {
        DecryptedHalf::Aead(r)
    }
}

/// `WriteHalf` of `TcpStream` with encryption
pub enum EncryptedHalf {
    Stream(StreamEncryptedWriter<TcpWriteHalf>),
    Aead(AeadEncryptedWriter<TcpWriteHalf>),
}

impl EncryptedWrite for EncryptedHalf {
    fn write_raw(&mut self, data: &[u8]) -> io::Result<usize> {
        mut_half_do!(self, EncryptedHalf, write_raw, data)
    }

    fn flush(&mut self) -> io::Result<()> {
        mut_half_do!(self, EncryptedHalf, flush)
    }

    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        mut_half_do!(self, EncryptedHalf, encrypt, data, buf)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        ref_half_do!(self, EncryptedHalf, buffer_size, data)
    }
}

impl From<StreamEncryptedWriter<TcpWriteHalf>> for EncryptedHalf {
    fn from(d: StreamEncryptedWriter<TcpWriteHalf>) -> EncryptedHalf {
        EncryptedHalf::Stream(d)
    }
}

impl From<AeadEncryptedWriter<TcpWriteHalf>> for EncryptedHalf {
    fn from(d: AeadEncryptedWriter<TcpWriteHalf>) -> EncryptedHalf {
        EncryptedHalf::Aead(d)
    }
}

/// Boxed future of `DecryptedHalf`
pub type DecryptedHalfFut = IoFuture<DecryptedHalf>;
/// Boxed future of `EncryptedHalf`
pub type EncryptedHalfFut = IoFuture<EncryptedHalf>;

/// Try to connect every IPs one by one
enum TcpStreamConnect<I: Iterator<Item = SocketAddr>> {
    Empty,
    Connect {
        last_err: Option<io::Error>,
        addr_iter: I,
        opt_stream_new: Option<(ConnectFuture, SocketAddr)>,
    },
}

impl<I: Iterator<Item = SocketAddr>> TcpStreamConnect<I> {
    fn new(iter: I) -> TcpStreamConnect<I> {
        TcpStreamConnect::Connect { last_err: None,
                                    addr_iter: iter,
                                    opt_stream_new: None, }
    }
}

impl<I: Iterator<Item = SocketAddr>> Future for TcpStreamConnect<I> {
    type Item = TcpStream;
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        use std::io::ErrorKind;

        match *self {
            TcpStreamConnect::Empty => unreachable!(),
            TcpStreamConnect::Connect { ref mut last_err,
                                        ref mut addr_iter,
                                        ref mut opt_stream_new, } => {
                loop {
                    // 1. Poll before doing anything else
                    if let Some((ref mut stream_new, ref addr)) = *opt_stream_new {
                        match stream_new.poll() {
                            Ok(Async::Ready(stream)) => return Ok(Async::Ready(stream)),
                            Ok(Async::NotReady) => return Ok(Async::NotReady),
                            Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Ok(Async::NotReady),
                            Err(err) => {
                                error!("Failed to connect {}: {}", addr, err);

                                *last_err = Some(err);
                            }
                        }
                    }

                    match addr_iter.next() {
                        None => break,
                        Some(addr) => {
                            *opt_stream_new = Some((TcpStream::connect(&addr), addr));
                        }
                    }
                }
            }
        }

        match mem::replace(self, TcpStreamConnect::Empty) {
            TcpStreamConnect::Empty => unreachable!(),
            TcpStreamConnect::Connect { last_err, .. } => {
                match last_err {
                    None => {
                        let err = io::Error::new(ErrorKind::Other, "connect TCP without any addresses");
                        Err(err)
                    }
                    Some(err) => Err(err),
                }
            }
        }
    }
}

fn connect_proxy_server(config: Arc<Config>,
                        svr_cfg: Arc<ServerConfig>)
                        -> impl Future<Item = TcpStream, Error = io::Error> + Send {
    let timeout = *svr_cfg.timeout();
    trace!("Connecting to proxy {:?}, timeout: {:?}", svr_cfg.addr(), timeout);
    match *svr_cfg.addr() {
        ServerAddr::SocketAddr(ref addr) => {
            let fut = try_timeout(TcpStream::connect(addr), timeout);
            boxed_future(fut)
        }
        ServerAddr::DomainName(ref domain, port) => {
            let fut = {
                try_timeout(resolve(config.clone(), &domain[..], port, false), timeout).and_then(move |vec_ipaddr| {
                    let fut = TcpStreamConnect::new(vec_ipaddr.into_iter());
                    try_timeout(fut, timeout)
                })
            };
            boxed_future(fut)
        }
    }
}

/// Handshake logic for ShadowSocks Client
pub fn proxy_server_handshake(remote_stream: TcpStream,
                              svr_cfg: Arc<ServerConfig>,
                              relay_addr: Address)
                              -> impl Future<Item = (DecryptedHalfFut, EncryptedHalfFut), Error = io::Error> + Send {
    let timeout = *svr_cfg.timeout();
    proxy_handshake(remote_stream, svr_cfg).and_then(move |(r_fut, w_fut)| {
        let w_fut = w_fut.and_then(move |enc_w| {
                                       // Send relay address to remote
                                       let mut buf = BytesMut::with_capacity(relay_addr.len());
                                       relay_addr.write_to_buf(&mut buf);

                                       trace!("Got encrypt stream and going to send addr: {:?}, buf: {:?}",
                                              relay_addr,
                                              buf);

                                       try_timeout(enc_w.write_all(buf), timeout).map(|(w, _)| w)
                                   });

        Ok((r_fut, boxed_future(w_fut)))
    })
}

/// ShadowSocks Client-Server handshake protocol
/// Exchange cipher IV and creates stream wrapper
pub fn proxy_handshake(remote_stream: TcpStream,
                       svr_cfg: Arc<ServerConfig>)
                       -> impl Future<Item = (DecryptedHalfFut, EncryptedHalfFut), Error = io::Error> + Send {
    futures::lazy(|| Ok(remote_stream.split())).and_then(move |(r, w)| {
        let timeout = svr_cfg.timeout().clone();

        let svr_cfg_cloned = svr_cfg.clone();

        let enc = {
            // Encrypt data to remote server

            // Send initialize vector to remote and create encryptor

            let method = svr_cfg.method();
            let prev_buf = match method.category() {
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

            try_timeout(write_all(w, prev_buf), timeout).and_then(
                move |(w, prev_buf)| match svr_cfg.method().category() {
                    CipherCategory::Stream => {
                        let local_iv = prev_buf;
                        Ok(From::from(StreamEncryptedWriter::new(w, svr_cfg.method(), svr_cfg.key(), &local_iv)))
                    }
                    CipherCategory::Aead => {
                        let local_salt = prev_buf;
                        let wtr = AeadEncryptedWriter::new(w, svr_cfg.method(), svr_cfg.key(), &local_salt[..]);
                        Ok(From::from(wtr))
                    }
                },
            )
        };

        let dec = {
            let svr_cfg = svr_cfg_cloned;

            // Decrypt data from remote server

            let method = svr_cfg.method();
            let prev_len = match method.category() {
                CipherCategory::Stream => method.iv_size(),
                CipherCategory::Aead => method.salt_size(),
            };

            try_timeout(read_exact(r, vec![0u8; prev_len]), timeout).and_then(move |(r, remote_iv)| {
                match svr_cfg.method().category() {
                    CipherCategory::Stream => {
                        trace!("Got initialize vector {:?}", ByteStr::new(&remote_iv));
                        let decrypt_stream = StreamDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                        Ok(From::from(decrypt_stream))
                    }
                    CipherCategory::Aead => {
                        trace!("Got salt {:?}", ByteStr::new(&remote_iv));
                        let dr = AeadDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                        Ok(From::from(dr))
                    }
                }
            })
        };

        Ok((boxed_future(dec), boxed_future(enc)))
    })
}

/// Establish tunnel between server and client
pub fn tunnel<CF, CFI, SF, SFI>(addr: Address, c2s: CF, s2c: SF) -> impl Future<Item = (), Error = io::Error> + Send
    where CF: Future<Item = CFI, Error = io::Error> + Send + 'static,
          SF: Future<Item = SFI, Error = io::Error> + Send + 'static
{
    let addr = Arc::new(addr);

    let cloned_addr = addr.clone();
    let c2s = c2s.then(move |res| {
                           match res {
                               Ok(..) => {
                                   // Continue reading response from remote server
                                   trace!("Relay {} client -> server is finished", cloned_addr);

                                   Ok(TunnelDirection::Client2Server)
                               }
                               Err(err) => {
                                   error!("Relay {} client -> server aborted: {}", cloned_addr, err);
                                   Err(err)
                               }
                           }
                       });

    let cloned_addr = addr.clone();
    let s2c = s2c.then(move |res| match res {
                           Ok(..) => {
                               trace!("Relay {} client <- server is finished", cloned_addr);

                               Ok(TunnelDirection::Server2Client)
                           }
                           Err(err) => {
                               error!("Relay {} client <- server aborted: {}", cloned_addr, err);
                               Err(err)
                           }
                       });

    c2s.select(s2c).and_then(move |(dir, _)| {
                     match dir {
                         TunnelDirection::Server2Client => {
                             trace!("Relay {} client <- server is closed, abort connection", addr)
                         }
                         TunnelDirection::Client2Server => {
                             trace!("Relay {} server -> client is closed, abort connection", addr)
                         }
                     }

                     Ok(())
                 })
       .map_err(|(err, _)| err)
}

/// Read until EOF, and ignore
pub enum IgnoreUntilEnd<R: Read> {
    Pending { r: R, amt: u64 },
    Empty,
}

impl<R: Read> Future for IgnoreUntilEnd<R> {
    type Item = u64;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            IgnoreUntilEnd::Empty => panic!("poll IgnoreUntilEnd after it is finished"),
            IgnoreUntilEnd::Pending { ref mut r, ref mut amt } => {
                let mut buf = [0u8; 4096];
                loop {
                    let n = try_nb!(r.read(&mut buf));
                    *amt += n as u64;

                    if n == 0 {
                        break;
                    }
                }
            }
        }

        match mem::replace(self, IgnoreUntilEnd::Empty) {
            IgnoreUntilEnd::Pending { amt, .. } => Ok(amt.into()),
            IgnoreUntilEnd::Empty => unreachable!(),
        }
    }
}

/// Ignore all data from the reader
pub fn ignore_until_end<R: Read>(r: R) -> IgnoreUntilEnd<R> {
    IgnoreUntilEnd::Pending { r: r, amt: 0 }
}

fn try_timeout<T, F>(fut: F, dur: Option<Duration>) -> impl Future<Item = T, Error = io::Error> + Send
    where F: Future<Item = T, Error = io::Error> + Send + 'static,
          T: 'static
{
    match dur {
        Some(dur) => boxed_future(io_timeout(fut, dur)),
        None => boxed_future(fut),
    }
}

fn io_timeout<T, F>(fut: F, dur: Duration) -> impl Future<Item = T, Error = io::Error> + Send
    where F: Future<Item = T, Error = io::Error> + Send + 'static,
          T: 'static
{
    use tokio::prelude::*;

    fut.deadline(Instant::now() + dur).map_err(|err| match err.into_inner() {
                    Some(e) => e,
                    None => io::Error::new(io::ErrorKind::TimedOut, "connection timed out"),
                })
}
