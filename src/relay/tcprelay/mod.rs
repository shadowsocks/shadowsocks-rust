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
use std::cmp;

use crypto::cipher;
use crypto::CryptoMode;
use relay::socks5::Address;
use relay::{BoxIoFuture, boxed_future};
use relay::dns_resolver::DnsResolver;
use config::{ServerConfig, ServerAddr};

use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_core::io::{read_exact, write_all, flush};
use tokio_core::io::{ReadHalf, WriteHalf};
use tokio_core::io::Io;

use futures::{self, Future, Poll};

use ip::IpAddr;

use self::stream::{EncryptedWriter, DecryptedReader};

pub mod local;
pub mod server;
mod stream;
mod http;
pub mod client;

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

fn connect_proxy_server(handle: &Handle,
                        svr_cfg: Rc<ServerConfig>,
                        dns_resolver: DnsResolver)
                        -> BoxIoFuture<TcpStream> {
    match svr_cfg.addr() {
        &ServerAddr::SocketAddr(ref addr) => Box::new(TcpStream::connect(addr, handle)),
        &ServerAddr::DomainName(ref domain, port) => {
            let handle = handle.clone();
            let fut = dns_resolver.resolve(&domain[..])
                .and_then(move |sockaddr| {
                    let sockaddr = match sockaddr {
                        IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                    };
                    TcpStream::connect(&sockaddr, &handle).boxed()
                });
            Box::new(fut)
        }
    }
}

/// Handshake logic for ShadowSocks Client
pub fn proxy_server_handshake(remote_stream: TcpStream,
                              svr_cfg: Rc<ServerConfig>,
                              relay_addr: Address)
                              -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    let fut = proxy_handshake(remote_stream, svr_cfg).and_then(|(r_fut, w_fut)| {
        let w_fut = w_fut.and_then(move |enc_w| {
            trace!("Got encrypt stream and going to send addr: {:?}",
                   relay_addr);

            // Send relay address to remote
            let local_buf = Vec::new();
            relay_addr.write_to(local_buf)
                .and_then(|buf| enc_w.write_all_encrypted(buf))
                .and_then(|(enc_w, _)| flush(enc_w))
        });
        Ok((r_fut, boxed_future(w_fut)))
    });
    Box::new(fut)
}

/// ShadowSocks Client-Server handshake protocol
/// Exchange cipher IV and creates stream wrapper
pub fn proxy_handshake(remote_stream: TcpStream,
                       svr_cfg: Rc<ServerConfig>)
                       -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    let fut = futures::lazy(move || {
        let (r, w) = remote_stream.split();

        let svr_cfg_cloned = svr_cfg.clone();

        let enc = futures::lazy(move || {
            // Encrypt data to remote server

            // Send initialize vector to remote and create encryptor

            let local_iv = svr_cfg.method().gen_init_vec();
            trace!("Going to send initialize vector: {:?}", local_iv);

            write_all(w, local_iv).and_then(move |(w, local_iv)| {
                let encryptor = cipher::with_type(svr_cfg.method(),
                                                  svr_cfg.key(),
                                                  &local_iv[..],
                                                  CryptoMode::Encrypt);

                Ok(EncryptedWriter::new(w, encryptor))
            })

        });

        let dec = futures::lazy(move || {
            let svr_cfg = svr_cfg_cloned;

            // Decrypt data from remote server
            let iv_len = svr_cfg.method().iv_size();
            read_exact(r, vec![0u8; iv_len]).and_then(move |(r, remote_iv)| {
                trace!("Got initialize vector {:?}", remote_iv);

                let decryptor = cipher::with_type(svr_cfg.method(),
                                                  svr_cfg.key(),
                                                  &remote_iv[..],
                                                  CryptoMode::Decrypt);
                let decrypt_stream = DecryptedReader::new(r, decryptor);

                Ok(decrypt_stream)
            })
        });

        Ok((boxed_future(dec), boxed_future(enc)))
    });
    Box::new(fut)
}

/// Copy exactly N bytes by encryption
pub enum CopyExactEncrypted<R, W>
    where R: Read,
          W: Write
{
    Pending {
        reader: R,
        writer: EncryptedWriter<W>,
        buf: [u8; 4096],
        remain: usize,
        pos: usize,
        cap: usize,
        enc_buf: Vec<u8>,
    },
    Empty,
}

impl<R, W> CopyExactEncrypted<R, W>
    where R: Read,
          W: Write
{
    pub fn new(r: R, w: EncryptedWriter<W>, amt: usize) -> CopyExactEncrypted<R, W> {
        CopyExactEncrypted::Pending {
            reader: r,
            writer: w,
            buf: [0u8; 4096],
            remain: amt,
            pos: 0,
            cap: 0,
            enc_buf: Vec::new(),
        }
    }
}

impl<R, W> Future for CopyExactEncrypted<R, W>
    where R: Read,
          W: Write
{
    type Item = (R, EncryptedWriter<W>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            &mut CopyExactEncrypted::Empty => panic!("poll after CopyExactEncrypted is finished"),
            &mut CopyExactEncrypted::Pending { ref mut reader,
                                               ref mut writer,
                                               ref mut buf,
                                               ref mut remain,
                                               ref mut pos,
                                               ref mut cap,
                                               ref mut enc_buf } => {
                loop {
                    // If our buffer is empty, then we need to read some data to
                    // continue.
                    if *pos == *cap && *remain != 0 {
                        let buf_len = cmp::min(*remain, buf.len());
                        let n = try_nb!(reader.read(&mut buf[..buf_len]));
                        if n == 0 {
                            // Unexpected EOF!
                            let err = io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected Eof");
                            return Err(err);
                        } else {
                            *pos = 0;
                            *remain -= n;

                            enc_buf.clear();
                            try!(writer.cipher_update(&buf[..n], enc_buf));
                            *cap = enc_buf.len();
                        }
                    }

                    // If our buffer has some data, let's write it out!
                    while *pos < *cap {
                        let i = try_nb!(writer.write(&enc_buf[*pos..*cap]).and_then(|x| writer.flush().map(|_| x)));
                        *pos += i;
                    }

                    // If we've written al the data and we've seen EOF, flush out the
                    // data and finish the transfer.
                    // done with the entire transfer.
                    if *pos == *cap && *remain == 0 {
                        try_nb!(writer.flush());
                        break; // The only path to execute the following logic
                    }
                }
            }
        }

        match mem::replace(self, CopyExactEncrypted::Empty) {
            CopyExactEncrypted::Pending { reader, writer, .. } => Ok((reader, writer).into()),
            CopyExactEncrypted::Empty => unreachable!(),
        }
    }
}

/// Copy all bytes from reader and write all encrypted data into writer
pub fn copy_exact_encrypted<R, W>(r: R, w: EncryptedWriter<W>, amt: usize) -> CopyExactEncrypted<R, W>
    where R: Read,
          W: Write
{
    CopyExactEncrypted::new(r, w, amt)
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