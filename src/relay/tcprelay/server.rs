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

//! TcpRelay server that running on the server side

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::collections::HashSet;

use config::{Config, ServerConfig};

use crypto::CryptoMode;
use crypto::cipher;

use super::stream::{EncryptedWriter, DecryptedReader};

use relay::socks5::Address;

use futures::{self, Future, BoxFuture};
use futures::stream::Stream;

use futures_cpupool::CpuPool;

use tokio_core::reactor::Handle;
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::io::Io;
use tokio_core::io::{ReadHalf, WriteHalf};
use tokio_core::io::{read_exact, write_all, copy};

use ip::IpAddr;

type ClientRead = ReadHalf<TcpStream>;
type ClientWrite = WriteHalf<TcpStream>;

type EncryptedHalf = EncryptedWriter<ClientWrite>;
type DecryptedHalf = DecryptedReader<ClientRead>;

/// TCP Relay backend
pub struct TcpRelayServer {
    config: Arc<Config>,
    cpu_pool: CpuPool,
}

impl TcpRelayServer {
    /// Creates an instance
    pub fn new(config: Arc<Config>, threads: usize) -> TcpRelayServer {
        TcpRelayServer {
            config: config,
            cpu_pool: CpuPool::new(threads),
        }
    }

    fn handshake((r, w): (ClientRead, ClientWrite),
                 svr_cfg: Arc<ServerConfig>)
                 -> BoxFuture<(DecryptedHalf, EncryptedHalf), io::Error> {
        let iv_len = svr_cfg.method.iv_size();
        read_exact(r, vec![0u8; iv_len])
            .and_then(move |(r, iv)| {
                trace!("Got handshake iv: {:?}", iv);
                let decryptor = cipher::with_type(svr_cfg.method,
                                                  svr_cfg.password.as_bytes(),
                                                  &iv[..],
                                                  CryptoMode::Decrypt);
                let decrypt_stream = DecryptedReader::new(r, decryptor);

                Ok((svr_cfg, decrypt_stream))
            })
            .and_then(|(svr_cfg, enc_r)| {
                let iv = svr_cfg.method.gen_init_vec();
                trace!("Going to send handshake iv: {:?}", iv);
                write_all(w, iv).and_then(move |(w, iv)| {
                    let encryptor = cipher::with_type(svr_cfg.method,
                                                      svr_cfg.password.as_bytes(),
                                                      &iv[..],
                                                      CryptoMode::Encrypt);
                    let encrypt_stream = EncryptedWriter::new(w, encryptor);

                    Ok((enc_r, encrypt_stream))
                })
            })
            .boxed()
    }

    fn resolve_address(addr: Address, cpu_pool: CpuPool) -> BoxFuture<SocketAddr, io::Error> {
        match addr {
            Address::SocketAddress(addr) => futures::finished(addr).boxed(),
            Address::DomainNameAddress(dname, port) => {
                cpu_pool.spawn(futures::lazy(move || {
                        let dname = format!("{}:{}", dname, port);
                        let mut addrs = try!(dname.to_socket_addrs());
                        addrs.next().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to resolve domain"))
                    }))
                    .boxed()
            }
        }
    }

    fn resolve_remote(cpu_pool: CpuPool,
                      addr: Address,
                      forbidden_ip: Arc<HashSet<IpAddr>>)
                      -> BoxFuture<SocketAddr, io::Error> {
        TcpRelayServer::resolve_address(addr, cpu_pool)
            .and_then(move |addr| {
                trace!("Resolved address as {}", addr);
                let ipaddr = match addr.clone() {
                    SocketAddr::V4(v4) => IpAddr::V4(v4.ip().clone()),
                    SocketAddr::V6(v6) => IpAddr::V6(v6.ip().clone()),
                };

                if forbidden_ip.contains(&ipaddr) {
                    info!("{} has been forbidden", ipaddr);
                    let err = io::Error::new(io::ErrorKind::Other, "Forbidden IP");
                    Err(err)
                } else {
                    Ok(addr)
                }
            })
            .boxed()
    }

    fn connect_remote(cpu_pool: CpuPool,
                      handle: Handle,
                      addr: Address,
                      forbidden_ip: Arc<HashSet<IpAddr>>)
                      -> Box<Future<Item = TcpStream, Error = io::Error>> {
        trace!("Connecting to remote {}", addr);
        Box::new(TcpRelayServer::resolve_remote(cpu_pool, addr, forbidden_ip)
            .and_then(move |addr| TcpStream::connect(&addr, &handle)))
    }

    pub fn handle_client(handle: &Handle,
                         cpu_pool: CpuPool,
                         s: TcpStream,
                         svr_cfg: Arc<ServerConfig>,
                         forbidden_ip: Arc<HashSet<IpAddr>>)
                         -> io::Result<()> {
        let peer_addr = try!(s.peer_addr());
        trace!("Got connection from {}", peer_addr);

        let cloned_handle = handle.clone();
        let fut = futures::lazy(|| Ok(s.split()))
            .and_then(move |(r, w)| TcpRelayServer::handshake((r, w), svr_cfg))
            .and_then(|(r, w)| Address::read_from(r).map(|(r, addr)| (r, w, addr)).map_err(From::from))
            .and_then(move |(r, w, addr)| {
                info!("Connecting {}", addr);
                let cloned_addr = addr.clone();
                TcpRelayServer::connect_remote(cpu_pool, cloned_handle, addr, forbidden_ip)
                    .map(|svr_s| (svr_s, r, w, cloned_addr))
            })
            .and_then(|(svr_s, r, w, addr)| {
                let (svr_r, svr_w) = svr_s.split();
                let c2s = copy(r, svr_w);
                let s2c = copy(svr_r, w);
                c2s.join(s2c)
                    .and_then(move |(c2s_amt, s2c_amt)| {
                        trace!("Relayed {} client -> remote {}bytes", addr, c2s_amt);
                        trace!("Relayed {} client <- remote {}bytes", addr, s2c_amt);
                        Ok(())
                    })
            });

        handle.spawn(fut.then(|res| {
            match res {
                Ok(..) => Ok(()),
                Err(err) => {
                    error!("Failed to handle client: {}", err);
                    Err(())
                }
            }
        }));

        Ok(())
    }

    /// Runs the server
    pub fn run(self, handle: Handle) -> Box<Future<Item = (), Error = io::Error>> {
        let mut fut: Option<Box<Future<Item = (), Error = io::Error>>> = None;

        for svr_cfg in &self.config.server {
            let listener = {
                let addr = &svr_cfg.addr;
                let listener = TcpListener::bind(addr, &handle).unwrap();
                trace!("ShadowSocks TCP Listening on {}", addr);
                listener
            };

            let svr_cfg = svr_cfg.clone();
            let handle = handle.clone();
            let forbidden_ip = self.config.forbidden_ip.clone();
            let cpu_pool = self.cpu_pool.clone();
            let listening = listener.incoming()
                .for_each(move |(socket, addr)| {
                    let server_cfg = svr_cfg.clone();
                    let forbidden_ip = forbidden_ip.clone();
                    let cpu_pool = cpu_pool.clone();

                    trace!("Got connection, addr: {}", addr);
                    trace!("Picked proxy server: {:?}", server_cfg);
                    TcpRelayServer::handle_client(&handle, cpu_pool, socket, server_cfg, forbidden_ip)
                })
                .map_err(|err| {
                    error!("Server run failed: {}", err);
                    err
                });

            fut = Some(match fut.take() {
                Some(fut) => Box::new(fut.join(listening).map(|_| ())) as Box<Future<Item = (), Error = io::Error>>,
                None => Box::new(listening) as Box<Future<Item = (), Error = io::Error>>,
            })
        }

        fut.expect("Must have at least one server")
    }
}
