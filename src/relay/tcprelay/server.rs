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

use std::sync::Arc;
use std::io::{self, Read, Write, BufReader};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::collections::HashSet;

use ip::IpAddr;

use coio::Scheduler;
use coio::net::{TcpListener, TcpStream, Shutdown};

use config::{Config, ServerConfig};
use relay::socks5;
use relay::tcprelay::cached_dns::CachedDns;
use relay::tcprelay::stream::{DecryptedReader, EncryptedWriter};
use crypto::cipher::{self, CipherType};
use crypto::CryptoMode;

use super::SharedTcpStream;

#[derive(Clone)]
pub struct TcpRelayServer {
    config: Config,
}

impl TcpRelayServer {
    pub fn new(c: Config) -> TcpRelayServer {
        if c.server.is_empty() {
            panic!("You have to provide a server configuration");
        }
        TcpRelayServer { config: c }
    }

    fn handshake(mut stream: SharedTcpStream,
                 encrypt_method: CipherType,
                 pwd: &[u8])
                 -> io::Result<(DecryptedReader<SharedTcpStream>, EncryptedWriter<SharedTcpStream>)> {
        // Decrypt
        let remote_iv = {
            let mut iv = Vec::with_capacity(encrypt_method.block_size());
            unsafe {
                iv.set_len(encrypt_method.block_size());
            }

            let mut total_len = 0;
            while total_len < encrypt_method.block_size() {
                match stream.read(&mut iv[total_len..]) {
                    Ok(0) => {
                        error!("Unexpected EOF while reading initialize vector");
                        let err = io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected Eof");
                        return Err(err);
                    }
                    Ok(n) => total_len += n,
                    Err(err) => {
                        error!("Error while reading initialize vector: {}", err);
                        return Err(err);
                    }
                }
            }
            iv
        };
        let decryptor = cipher::with_type(encrypt_method, pwd, &remote_iv[..], CryptoMode::Decrypt);
        let decrypt_stream = DecryptedReader::new(stream.clone(), decryptor);

        // Encrypt
        let iv = encrypt_method.gen_init_vec();
        let encryptor = cipher::with_type(encrypt_method, pwd, &iv[..], CryptoMode::Encrypt);
        if let Err(err) = stream.write_all(&iv[..]) {
            error!("Error occurs while writing initialize vector: {}", err);
            return Err(err);
        }

        let encrypt_stream = EncryptedWriter::new(stream, encryptor);
        Ok((decrypt_stream, encrypt_stream))
    }

    fn connect_remote(addr: &socks5::Address,
                      dnscache: &Arc<CachedDns>,
                      forbidden_ip: &Arc<HashSet<IpAddr>>)
                      -> io::Result<TcpStream> {
        info!("Connecting to {}", addr);

        match addr {
            &socks5::Address::SocketAddress(ref addr) => {
                if forbidden_ip.contains(&::relay::take_ip_addr(addr)) {
                    info!("{} has been blocked by `forbidden_ip`", addr);
                    let err = io::Error::new(io::ErrorKind::Other, "IP blocked");
                    return Err(err);
                }

                match TcpStream::connect(&addr) {
                    Ok(stream) => Ok(stream),
                    Err(err) => {
                        error!("Unable to connect {:?}: {}", addr, err);
                        Err(err)
                    }
                }
            }
            &socks5::Address::DomainNameAddress(ref dname, ref port) => {
                let addrs = match dnscache.resolve(&dname) {
                    Some(addrs) => addrs,
                    None => {
                        error!("Failed to resolve {}", dname);
                        let err = io::Error::new(io::ErrorKind::Other, "DNS resolve error");
                        return Err(err);
                    }
                };

                let processing = || {
                    let mut last_err: Option<io::Result<TcpStream>> = None;
                    for addr in addrs.into_iter() {
                        let addr = match addr {
                            SocketAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr.ip().clone(), *port)),
                            SocketAddr::V6(addr) => {
                                SocketAddr::V6(SocketAddrV6::new(addr.ip().clone(),
                                                                 *port,
                                                                 addr.flowinfo(),
                                                                 addr.scope_id()))
                            }
                        };

                        if forbidden_ip.contains(&::relay::take_ip_addr(&addr)) {
                            info!("{} has been blocked by `forbidden_ip`", addr);
                            last_err = Some(Err(io::Error::new(io::ErrorKind::Other, "Blocked by `forbidden_ip`")));
                            continue;
                        }

                        match TcpStream::connect(addr) {
                            Ok(stream) => return Ok(stream),
                            Err(err) => {
                                error!("Unable to connect {:?}: {}", addr, err);
                                last_err = Some(Err(err));
                            }
                        }
                    }

                    last_err.unwrap()
                };

                processing()
            }
        }
    }

    fn accept_loop(s: ServerConfig, forbidden_ip: Arc<HashSet<IpAddr>>) {
        let acceptor = TcpListener::bind(&(&s.addr[..], s.port))
            .unwrap_or_else(|err| panic!("Failed to bind a TCP socket: {}", err));

        info!("Shadowsocks listening on {}:{}", s.addr, s.port);

        let dnscache_arc = Arc::new(CachedDns::with_capacity(s.dns_cache_capacity));

        let pwd = s.method.bytes_to_key(s.password.as_bytes());
        let timeout = s.timeout;
        let method = s.method;

        info!("Method {}, Timeout: {:?}", method, timeout);

        for s in acceptor.incoming() {
            let stream = match s {
                Ok((s, addr)) => {
                    debug!("Got connection from {:?}", addr);
                    s
                }
                Err(err) => {
                    panic!("Error occurs while accepting: {}", err);
                }
            };

            if let Err(err) = stream.set_read_timeout(timeout) {
                error!("Failed to set read timeout: {:?}", err);
                continue;
            }

            if let Err(err) = stream.set_nodelay(true) {
                error!("Failed to set no delay: {}", err);
                continue;
            }

            let pwd = pwd.clone();
            let encrypt_method = method;
            let dnscache = dnscache_arc.clone();
            let forbidden_ip = forbidden_ip.clone();

            Scheduler::spawn(move || {
                let (mut decrypt_stream, mut encrypt_stream) =
                    match TcpRelayServer::handshake(SharedTcpStream::new(stream), encrypt_method, &pwd[..]) {
                        Ok(x) => x,
                        Err(err) => {
                            error!("Failed to do handshake, {}", err);
                            return;
                        }
                    };

                let addr = match socks5::Address::read_from(&mut decrypt_stream) {
                    Ok(addr) => addr,
                    Err(err) => {
                        error!("Error occurs while parsing request header, maybe wrong crypto \
                                method or password: {}",
                               err);
                        return;
                    }
                };

                let remote_stream = match TcpRelayServer::connect_remote(&addr, &dnscache, &forbidden_ip) {
                    Ok(s) => SharedTcpStream::new(s),
                    Err(err) => {
                        error!("Failed to connect to {}: {}", addr, err);
                        return;
                    }
                };

                let mut remote_writer = remote_stream.clone();
                let addr_cloned = addr.clone();

                Scheduler::spawn(move || {
                    let mut remote_reader = BufReader::new(remote_stream);
                    match ::relay::copy_once(&mut remote_reader, &mut encrypt_stream) {
                        Ok(0) => {}
                        Ok(n) => {
                            let remote_addr = encrypt_stream.get_ref().peer_addr().unwrap();
                            let client_addr = remote_reader.get_ref().peer_addr().unwrap();

                            trace!("{} local <- remote: relayed {} bytes from {} to {}",
                                   addr,
                                   n,
                                   remote_addr,
                                   client_addr);

                            loop {
                                match ::relay::copy_once(&mut remote_reader, &mut encrypt_stream) {
                                    Ok(0) => {
                                        trace!("{} local <- remote: EOF", addr);
                                        break;
                                    }
                                    Ok(n) => {
                                        trace!("{} local <- remote: relayed {} bytes from {} to {}",
                                               addr,
                                               n,
                                               remote_addr,
                                               client_addr)
                                    }
                                    Err(err) => {
                                        error!("{} local <- remote: {}", addr, err);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("{} local <- remote: {}", addr, err);
                        }
                    }

                    debug!("{} local <- remote is closing", addr);

                    let _ = encrypt_stream.get_mut().shutdown(Shutdown::Both);
                    let _ = remote_reader.get_mut().shutdown(Shutdown::Both);
                });

                Scheduler::spawn(move || {
                    match ::relay::copy_once(&mut decrypt_stream, &mut remote_writer) {
                        Ok(0) => {}
                        Ok(n) => {
                            let remote_addr = remote_writer.peer_addr().unwrap();
                            let client_addr = decrypt_stream.get_ref().peer_addr().unwrap();

                            debug!("{} local -> remote: relayed {} bytes from {} to {}",
                                   addr_cloned,
                                   n,
                                   remote_addr,
                                   client_addr);

                            loop {
                                match ::relay::copy_once(&mut decrypt_stream, &mut remote_writer) {
                                    Ok(0) => {
                                        trace!("{} local -> remote: EOF", addr_cloned);
                                        break;
                                    }
                                    Ok(n) => {
                                        debug!("{} local -> remote: relayed {} bytes from {} to {}",
                                               addr_cloned,
                                               n,
                                               remote_addr,
                                               client_addr);
                                    }
                                    Err(err) => {
                                        error!("{} local -> remote: {}", addr_cloned, err);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("{} local -> remote: {}", addr_cloned, err);
                        }
                    }

                    debug!("{} local -> remote is closing", addr_cloned);

                    let _ = remote_writer.shutdown(Shutdown::Both);
                    let _ = decrypt_stream.get_mut().shutdown(Shutdown::Both);
                });
            });
        }
    }
}

impl TcpRelayServer {
    pub fn run(&self) {
        let mut futs = Vec::with_capacity(self.config.server.len());
        let forbidden_ip = Arc::new(self.config.forbidden_ip.clone());

        for s in &self.config.server {
            let s = s.clone();
            let forbidden_ip = forbidden_ip.clone();
            let fut = Scheduler::spawn(move || {
                TcpRelayServer::accept_loop(s, forbidden_ip);
            });
            futs.push(fut);
        }

        for fut in futs {
            fut.join().unwrap();
        }
    }
}
