//! Relay for TCP implementation

use std::io::{self, BufRead, Read};
use std::iter::{IntoIterator, Iterator};
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use config::{ServerAddr, ServerConfig};
use crypto::CipherCategory;
use relay::{boxed_future, BoxIoFuture};
use relay::Context;
use relay::dns_resolver::resolve;
use relay::socks5::Address;

use tokio_core::net::{TcpStream, TcpStreamNew};
use tokio_core::reactor::{Handle, Timeout};
use tokio_io::AsyncRead;
use tokio_io::io::{ReadHalf, WriteHalf};
use tokio_io::io::{read_exact, write_all};

use futures::{self, Async, Future, Poll};

use bytes::{BufMut, BytesMut};

use byte_string::ByteStr;

pub use self::crypto_io::{DecryptedRead, EncryptedWrite};

use self::aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter};
use self::stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter};

pub mod local;
mod socks5_local;
pub mod server;
mod stream;
pub mod client;
mod crypto_io;
mod aead;
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
pub type DecryptedHalfFut = BoxIoFuture<DecryptedHalf>;
/// Boxed future of `EncryptedHalf`
pub type EncryptedHalfFut = BoxIoFuture<EncryptedHalf>;

/// Try to connect every IPs one by one
enum TcpStreamConnect<I: Iterator<Item = SocketAddr>> {
    Empty,
    Connect {
        last_err: Option<io::Error>,
        addr_iter: I,
        opt_stream_new: Option<TcpStreamNew>,
        handle: Handle,
    },
}

impl<I: Iterator<Item = SocketAddr>> TcpStreamConnect<I> {
    fn new(iter: I, handle: &Handle) -> TcpStreamConnect<I> {
        TcpStreamConnect::Connect {
            last_err: None,
            addr_iter: iter,
            opt_stream_new: None,
            handle: handle.clone(),
        }
    }
}

impl<I: Iterator<Item = SocketAddr>> Future for TcpStreamConnect<I> {
    type Item = TcpStream;
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        use std::io::ErrorKind;

        match *self {
            TcpStreamConnect::Empty => unreachable!(),
            TcpStreamConnect::Connect {
                ref mut last_err,
                ref mut addr_iter,
                ref mut opt_stream_new,
                ref handle,
            } => {
                loop {
                    // 1. Poll before doing anything else
                    if let Some(ref mut stream_new) = *opt_stream_new {
                        match stream_new.poll() {
                            Ok(Async::Ready(stream)) => return Ok(Async::Ready(stream)),
                            Ok(Async::NotReady) => return Ok(Async::NotReady),
                            Err(ref err) if err.kind() == ErrorKind::WouldBlock => return Ok(Async::NotReady),
                            Err(err) => {
                                *last_err = Some(err);
                            }
                        }
                    }

                    match addr_iter.next() {
                        None => break,
                        Some(addr) => {
                            *opt_stream_new = Some(TcpStream::connect(&addr, &handle));
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

fn connect_proxy_server(svr_cfg: Rc<ServerConfig>) -> BoxIoFuture<TcpStream> {
    let timeout = *svr_cfg.timeout();
    trace!("Connecting to proxy {:?}, timeout: {:?}", svr_cfg.addr(), timeout);
    match *svr_cfg.addr() {
        ServerAddr::SocketAddr(ref addr) => {
            Context::with(|ctx| {
                              let handle = ctx.handle();
                              try_timeout(TcpStream::connect(addr, handle), timeout, handle)
                          })
        }
        ServerAddr::DomainName(ref domain, port) => {
            let fut = Context::with(|ctx| {
                let handle = ctx.handle().clone();
                try_timeout(resolve(&domain[..], port, false), timeout, &handle).and_then(move |vec_ipaddr| {
                    let fut = TcpStreamConnect::new(vec_ipaddr.into_iter(), &handle);
                    try_timeout(fut, timeout, &handle)
                })
            });
            boxed_future(fut)
        }
    }
}

/// Handshake logic for ShadowSocks Client
pub fn proxy_server_handshake(remote_stream: TcpStream,
                              svr_cfg: Rc<ServerConfig>,
                              relay_addr: Address)
                              -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    let timeout = *svr_cfg.timeout();
    let fut = proxy_handshake(remote_stream, svr_cfg).and_then(move |(r_fut, w_fut)| {
        let w_fut = w_fut.and_then(move |enc_w| {
            // Send relay address to remote
            let mut buf = BytesMut::with_capacity(relay_addr.len());
            relay_addr.write_to_buf(&mut buf);

            trace!("Got encrypt stream and going to send addr: {:?}, buf: {:?}", relay_addr, buf);

            Context::with(|ctx| try_timeout(enc_w.write_all(buf), timeout, ctx.handle()).map(|(w, _)| w))
        });

        Ok((r_fut, boxed_future(w_fut)))
    });
    boxed_future(fut)
}

/// ShadowSocks Client-Server handshake protocol
/// Exchange cipher IV and creates stream wrapper
pub fn proxy_handshake(remote_stream: TcpStream,
                       svr_cfg: Rc<ServerConfig>)
                       -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    let fut = futures::lazy(|| Ok(remote_stream.split())).and_then(move |(r, w)| {
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

            Context::with(|ctx| {
                try_timeout(write_all(w, prev_buf), timeout, ctx.handle()).and_then(
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
            })
        };

        let dec = {
            let svr_cfg = svr_cfg_cloned;

            // Decrypt data from remote server

            let method = svr_cfg.method();
            let prev_len = match method.category() {
                CipherCategory::Stream => method.iv_size(),
                CipherCategory::Aead => method.salt_size(),
            };

            Context::with(|ctx| {
                try_timeout(read_exact(r, vec![0u8; prev_len]), timeout, ctx.handle()).and_then(
                    move |(r, remote_iv)| match svr_cfg.method().category() {
                        CipherCategory::Stream => {
                            trace!("Got initialize vector {:?}", ByteStr::new(&remote_iv));
                            let decrypt_stream =
                                StreamDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                            Ok(From::from(decrypt_stream))
                        }
                        CipherCategory::Aead => {
                            trace!("Got salt {:?}", ByteStr::new(&remote_iv));
                            let dr = AeadDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                            Ok(From::from(dr))
                        }
                    },
                )
            })
        };

        Ok((boxed_future(dec), boxed_future(enc)))
    });

    boxed_future(fut)
}

/// Establish tunnel between server and client
pub fn tunnel<CF, CFI, SF, SFI>(addr: Address, c2s: CF, s2c: SF) -> BoxIoFuture<()>
where
    CF: Future<Item = CFI, Error = io::Error> + 'static,
    SF: Future<Item = SFI, Error = io::Error> + 'static,
{
    let addr = Rc::new(addr);

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

    let fut = c2s.select(s2c)
                 .and_then(move |(dir, _)| {
        match dir {
            TunnelDirection::Server2Client => trace!("Relay {} client <- server is closed, abort connection", addr),
            TunnelDirection::Client2Server => trace!("Relay {} server -> client is closed, abort connection", addr),
        }

        Ok(())
    })
                 .map_err(|(err, _)| err);

    boxed_future(fut)
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
            IgnoreUntilEnd::Pending {
                ref mut r,
                ref mut amt,
            } => {
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

fn try_timeout<T, F>(fut: F, dur: Option<Duration>, handle: &Handle) -> BoxIoFuture<T>
where
    F: Future<Item = T, Error = io::Error> + 'static,
    T: 'static,
{
    match dur {
        Some(dur) => io_timeout(fut, dur, handle),
        None => boxed_future(fut),
    }
}

fn io_timeout<T, F>(fut: F, dur: Duration, handle: &Handle) -> BoxIoFuture<T>
where
    F: Future<Item = T, Error = io::Error> + 'static,
    T: 'static,
{
    let fut = fut.select(Timeout::new(dur, handle)
                         .unwrap() // It must be succeeded!
                         .and_then(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))))
                 .then(|res| match res {
                           Ok((t, _)) => Ok(t),
                           Err((err, _)) => Err(err),
                       });
    boxed_future(fut)
}
