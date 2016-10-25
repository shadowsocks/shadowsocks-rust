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
use std::sync::Arc;
use std::mem;

use crypto::cipher;
use crypto::CryptoMode;
use relay::socks5::Address;
use relay::BoxIoFuture;
use config::ServerConfig;

use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_core::io::{read_exact, write_all, flush};
use tokio_core::io::{ReadHalf, WriteHalf};
use tokio_core::io::Io;

use futures::{self, Future, BoxFuture, Poll};

use self::stream::{EncryptedWriter, DecryptedReader};

// mod cached_dns;
pub mod local;
pub mod server;
mod stream;
mod http;

#[derive(Debug, Copy, Clone)]
pub enum TunnelDirection {
    Client2Server,
    Server2Client,
}

pub type DecryptedHalf = DecryptedReader<ReadHalf<TcpStream>>;
pub type EncryptedHalf = EncryptedWriter<WriteHalf<TcpStream>>;

pub type DecryptedHalfFut = BoxFuture<DecryptedHalf, io::Error>;
pub type EncryptedHalfFut = BoxFuture<EncryptedHalf, io::Error>;

fn connect_proxy_server(handle: &Handle, svr_cfg: Arc<ServerConfig>) -> BoxIoFuture<TcpStream> {
    TcpStream::connect(&svr_cfg.addr, handle).boxed()
}

/// Handshake logic for ShadowSocks Client
pub fn proxy_server_handshake(remote_stream: TcpStream,
                              svr_cfg: Arc<ServerConfig>,
                              relay_addr: Address)
                              -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    proxy_handshake(remote_stream, svr_cfg)
        .and_then(|(r_fut, w_fut)| {
            let w_fut = w_fut.and_then(move |enc_w| {
                    trace!("Got encrypt stream and going to send addr: {:?}",
                           relay_addr);

                    // Send relay address to remote
                    relay_addr.write_to(enc_w).and_then(flush)
                })
                .boxed();

            Ok((r_fut, w_fut))
        })
        .boxed()
}

/// ShadowSocks Client-Server handshake protocol
/// Exchange cipher IV and creates stream wrapper
pub fn proxy_handshake(remote_stream: TcpStream,
                       svr_cfg: Arc<ServerConfig>)
                       -> BoxIoFuture<(DecryptedHalfFut, EncryptedHalfFut)> {
    futures::lazy(move || {
            let (r, w) = remote_stream.split();

            let svr_cfg_cloned = svr_cfg.clone();

            let enc = futures::lazy(move || {
                // Encrypt data to remote server

                // Send initialize vector to remote and create encryptor

                let local_iv = svr_cfg.method.gen_init_vec();
                trace!("Going to send initialize vector: {:?}", local_iv);

                write_all(w, local_iv)
                    .and_then(|(w, local_iv)| flush(w).map(move |w| (w, local_iv)))
                    .and_then(move |(w, local_iv)| {
                        let encryptor = cipher::with_type(svr_cfg.method,
                                                          svr_cfg.password.as_bytes(),
                                                          &local_iv[..],
                                                          CryptoMode::Encrypt);

                        Ok(EncryptedWriter::new(w, encryptor))
                    })

            });

            let dec = futures::lazy(move || {
                let svr_cfg = svr_cfg_cloned;

                // Decrypt data from remote server
                let iv_len = svr_cfg.method.iv_size();
                read_exact(r, vec![0u8; iv_len]).and_then(move |(r, remote_iv)| {
                    trace!("Got initialize vector {:?}", remote_iv);

                    let decryptor = cipher::with_type(svr_cfg.method,
                                                      svr_cfg.password.as_bytes(),
                                                      &remote_iv[..],
                                                      CryptoMode::Decrypt);
                    let decrypt_stream = DecryptedReader::new(r, decryptor);

                    Ok(decrypt_stream)
                })
            });

            Ok((dec.boxed(), enc.boxed()))
        })
        .boxed()
}

/// Copy exactly N bytes
pub enum CopyExact<R, W>
    where R: Read,
          W: Write
{
    Pending {
        reader: R,
        writer: W,
        buf: [u8; 4096],
        remain: usize,
        pos: usize,
        cap: usize,
    },
    Empty,
}

impl<R, W> CopyExact<R, W>
    where R: Read,
          W: Write
{
    pub fn new(r: R, w: W, amt: usize) -> CopyExact<R, W> {
        CopyExact::Pending {
            reader: r,
            writer: w,
            buf: [0u8; 4096],
            remain: amt,
            pos: 0,
            cap: 0,
        }
    }
}

impl<R, W> Future for CopyExact<R, W>
    where R: Read,
          W: Write
{
    type Item = (R, W);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            &mut CopyExact::Empty => panic!("poll after CopyExact is finished"),
            &mut CopyExact::Pending { ref mut reader,
                                      ref mut writer,
                                      ref mut buf,
                                      ref mut remain,
                                      ref mut pos,
                                      ref mut cap } => {
                loop {
                    // If our buffer is empty, then we need to read some data to
                    // continue.
                    if *pos == *cap && *remain != 0 {
                        let buf_len = if *remain > buf.len() {
                            buf.len()
                        } else {
                            *remain
                        };
                        let n = try_nb!(reader.read(&mut buf[..buf_len]));
                        if n == 0 {
                            // Unexpected EOF!
                            let err = io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected Eof");
                            return Err(err);
                        } else {
                            *pos = 0;
                            *cap = n;
                            *remain -= n;
                        }
                    }

                    // If our buffer has some data, let's write it out!
                    while *pos < *cap {
                        let i = try_nb!(writer.write(&buf[*pos..*cap]).and_then(|x| writer.flush().map(|_| x)));
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

        match mem::replace(self, CopyExact::Empty) {
            CopyExact::Pending { reader, writer, .. } => Ok((reader, writer).into()),
            CopyExact::Empty => unreachable!(),
        }
    }
}

pub fn copy_exact<R, W>(r: R, w: W, amt: usize) -> CopyExact<R, W>
    where R: Read,
          W: Write
{
    CopyExact::new(r, w, amt)
}

pub fn tunnel<CF, SF>(addr: Address, c2s: CF, s2c: SF) -> BoxIoFuture<()>
    where CF: Future<Item = u64, Error = io::Error> + Send + 'static,
          SF: Future<Item = u64, Error = io::Error> + Send + 'static
{
    let addr = Arc::new(addr);

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

    c2s.select(s2c)
        .map_err(|(err, _)| err)
        .and_then(move |(dir, next)| {
            match dir {
                TunnelDirection::Client2Server => next.map(move |_| ()).boxed(),
                // Shutdown connection directly because remote server has disconnected
                TunnelDirection::Server2Client => futures::finished(()).boxed(),
            }
        })
        .and_then(move |_| {
            trace!("Relay {} client <-> server are all finished, closing", addr);
            Ok(())
        })
        .boxed()
}
