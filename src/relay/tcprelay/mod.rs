// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! TcpRelay implementation

use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::mem;
use std::time::Duration;

use crypto::cipher;
use crypto::CryptoMode;
use relay::socks5::Address;
use relay::{BoxIoFuture, boxed_future};
use relay::dns_resolver::DnsResolver;
use config::{ServerConfig, ServerAddr};

use tokio_core::net::TcpStream;
use tokio_core::reactor::{Handle, Timeout};
use tokio_core::io::{read_exact, write_all, read};
use tokio_core::io::{ReadHalf, WriteHalf};
use tokio_core::io::Io;

use futures::{self, Future, Poll};

use net2::TcpBuilder;

use ip::IpAddr;

use self::stream::{EncryptedWriter, DecryptedReader};

pub mod local;
mod socks5_local;
pub mod server;
mod stream;
pub mod client;

const BUFFER_SIZE: usize = 4096;

/// Directions in the tunnel
#[derive(Debug, Copy, Clone)]
pub enum TunnelDirection {
    /// Client -> Server
    Client2Server,
    /// Client <- Server
    Server2Client,
}

/// ReadHalf of TcpStream with decryption
pub type DecryptedHalf = DecryptedReader<ReadHalf<TcpStream>>;
/// WriteHalf of TcpStream with encryption
pub type EncryptedHalf = EncryptedWriter<WriteHalf<TcpStream>>;

/// Boxed future of DecryptedHalf
pub type DecryptedHalfFut = BoxIoFuture<DecryptedHalf>;
/// Boxed future of EncryptedHalf
pub type EncryptedHalfFut = BoxIoFuture<EncryptedHalf>;

fn connect_proxy_server(handle: &Handle, svr_cfg: Rc<ServerConfig>) -> BoxIoFuture<TcpStream> {
    let timeout = svr_cfg.timeout().clone();
    trace!("Connecting to proxy {:?}, timeout: {:?}",
           svr_cfg.addr(),
           timeout);
    match svr_cfg.addr() {
        &ServerAddr::SocketAddr(ref addr) => try_timeout(TcpStream::connect(addr, handle), timeout, handle),
        &ServerAddr::DomainName(ref domain, port) => {
            let handle = handle.clone();
            let fut = try_timeout(DnsResolver::resolve(&domain[..]), timeout, &handle).and_then(move |sockaddr| {
                let sockaddr = match sockaddr {
                    IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                    IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                };
                try_timeout(TcpStream::connect(&sockaddr, &handle), timeout, &handle)
            });
            boxed_future(fut)
        }
    }
}

/// Handshake logic for ShadowSocks Client
pub fn proxy_server_handshake(remote_stream: TcpStream,
                              svr_cfg: Rc<ServerConfig>,
                              relay_addr: Address,
                              handle: Handle)
                              -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    let timeout = svr_cfg.timeout().clone();
    let fut = proxy_handshake(remote_stream, svr_cfg, handle.clone()).and_then(move |(r_fut, w_fut)| {;
        let w_fut = w_fut.and_then(move |enc_w| {
            trace!("Got encrypt stream and going to send addr: {:?}",
                   relay_addr);

            // Send relay address to remote
            let local_buf = Vec::new();
            relay_addr.write_to(local_buf)
                .and_then(move |buf| try_timeout(enc_w.write_all_encrypted(buf), timeout, &handle))
                .map(|(w, _)| w)
        });

        Ok((r_fut, boxed_future(w_fut)))
    });
    boxed_future(fut)
}

/// ShadowSocks Client-Server handshake protocol
/// Exchange cipher IV and creates stream wrapper
pub fn proxy_handshake(remote_stream: TcpStream,
                       svr_cfg: Rc<ServerConfig>,
                       handle: Handle)
                       -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    let fut = futures::lazy(|| Ok(remote_stream.split())).and_then(move |(r, w)| {

        let timeout = svr_cfg.timeout().clone();

        let svr_cfg_cloned = svr_cfg.clone();

        let enc = {
            // Encrypt data to remote server

            // Send initialize vector to remote and create encryptor

            let local_iv = svr_cfg.method().gen_init_vec();
            trace!("Going to send initialize vector: {:?}", local_iv);

            try_timeout(write_all(w, local_iv), timeout.clone(), &handle).and_then(move |(w, local_iv)| {
                let encryptor = cipher::with_type(svr_cfg.method(),
                                                  svr_cfg.key(),
                                                  &local_iv[..],
                                                  CryptoMode::Encrypt);

                Ok(EncryptedWriter::new(w, encryptor))
            })
        };

        let dec = {
            let svr_cfg = svr_cfg_cloned;

            // Decrypt data from remote server
            let iv_len = svr_cfg.method().iv_size();
            try_timeout(read_exact(r, vec![0u8; iv_len]), timeout, &handle).and_then(move |(r, remote_iv)| {
                trace!("Got initialize vector {:?}", remote_iv);

                let decryptor = cipher::with_type(svr_cfg.method(),
                                                  svr_cfg.key(),
                                                  &remote_iv[..],
                                                  CryptoMode::Decrypt);
                let decrypt_stream = DecryptedReader::new(r, decryptor);

                Ok(decrypt_stream)
            })
        };

        Ok((boxed_future(dec), boxed_future(enc)))
    });

    boxed_future(fut)
}

/// Establish tunnel between server and client
pub fn tunnel<CF, SF>(addr: Address, c2s: CF, s2c: SF) -> BoxIoFuture<()>
    where CF: Future<Item = u64, Error = io::Error> + 'static,
          SF: Future<Item = u64, Error = io::Error> + 'static
{
    let addr = Rc::new(addr);

    let cloned_addr = addr.clone();
    let c2s = c2s.then(move |res| {
        match res {
            Ok(amt) => {
                // Continue reading response from remote server
                trace!("Relay {} client -> server is finished, relayed {} bytes",
                       cloned_addr,
                       amt);

                Ok(TunnelDirection::Client2Server)
            }
            Err(err) => {
                error!("Relay {} client -> server aborted: {}", cloned_addr, err);
                Err(err)
            }
        }
    });

    let cloned_addr = addr.clone();
    let s2c = s2c.then(move |res| {
        match res {
            Ok(amt) => {
                trace!("Relay {} client <- server is finished, relayed {} bytes",
                       cloned_addr,
                       amt);

                Ok(TunnelDirection::Server2Client)
            }
            Err(err) => {
                error!("Relay {} client <- server aborted: {}", cloned_addr, err);
                Err(err)
            }
        }
    });

    let fut = c2s.select(s2c)
        .and_then(|(dir, _)| {
            match dir {
                TunnelDirection::Server2Client => trace!("client <- server is closed, abort connection"),
                TunnelDirection::Client2Server => trace!("server -> client is closed, abort connection"),
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
        match self {
            &mut IgnoreUntilEnd::Empty => panic!("poll IgnoreUntilEnd after it is finished"),
            &mut IgnoreUntilEnd::Pending { ref mut r, ref mut amt } => {
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

#[cfg(unix)]
fn reuse_port(builder: &TcpBuilder) -> io::Result<&TcpBuilder> {
    use net2::unix::UnixTcpBuilderExt;
    builder.reuse_port(true)
}

#[cfg(windows)]
fn reuse_port(builder: &TcpBuilder) -> io::Result<&TcpBuilder> {
    Ok(builder)
}

fn try_timeout<T, F>(fut: F, dur: Option<Duration>, handle: &Handle) -> BoxIoFuture<T>
    where F: Future<Item = T, Error = io::Error> + 'static,
          T: 'static
{
    match dur {
        Some(dur) => io_timeout(fut, dur, handle),
        None => boxed_future(fut),
    }
}

fn io_timeout<T, F>(fut: F, dur: Duration, handle: &Handle) -> BoxIoFuture<T>
    where F: Future<Item = T, Error = io::Error> + 'static,
          T: 'static
{
    let fut = fut.select(Timeout::new(dur, handle)
            .unwrap() // It must be succeeded!
            .and_then(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))))
        .then(|res| {
            match res {
                Ok((t, _)) => Ok(t),
                Err((err, _)) => Err(err),
            }
        });
    boxed_future(fut)
}

fn copy_timeout<R, W>(r: R, w: W, timeout: Option<Duration>, handle: Handle) -> BoxIoFuture<u64>
    where R: Read + 'static,
          W: Write + 'static
{
    let fut = try_timeout(read(r, vec![0u8; BUFFER_SIZE]), timeout.clone(), &handle)
        .and_then(move |(r, mut buf, n)| {
            if n == 0 {
                boxed_future(futures::finished(n as u64))
            } else {
                buf.resize(n, 0);
                let fut = try_timeout(write_all(w, buf), timeout.clone(), &handle)
                    .and_then(move |(w, _)| copy_timeout(r, w, timeout, handle).map(move |x| x + n as u64));
                boxed_future(fut)
            }
        });
    boxed_future(fut)
}