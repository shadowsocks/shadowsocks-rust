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

// use std::sync::Arc;
use std::net::{TcpListener, TcpStream, Shutdown};
use std::io::{Read, Write, BufStream, ErrorKind, self};
use std::thread::{self, Builder};

use config::{Config, ServerConfig};
use relay::Relay;
use relay::socks5;
// use relay::tcprelay::cached_dns::CachedDns;
use relay::tcprelay::stream::{DecryptedReader, EncryptedWriter};
use crypto::cipher;
use crypto::CryptoMode;

#[derive(Clone)]
pub struct TcpRelayServer {
    config: Config,
}

impl TcpRelayServer {
    pub fn new(c: Config) -> TcpRelayServer {
        if c.server.is_empty() {
            panic!("You have to provide a server configuration");
        }
        TcpRelayServer {
            config: c,
        }
    }

    fn accept_loop(s: ServerConfig) {
        let acceptor = TcpListener::bind(&(&s.addr[..], s.port))
                                    .unwrap_or_else(|err| panic!("Failed to bind: {:?}", err));

        info!("Shadowsocks listening on {}", s.addr);

        // let dnscache_arc = Arc::new(CachedDns::with_capacity(s.dns_cache_capacity));

        let pwd = s.method.bytes_to_key(s.password.as_bytes());
        let timeout = s.timeout;
        let method = s.method;
        for s in acceptor.incoming() {
            let mut stream = s.unwrap();
            let _ = stream.set_keepalive(timeout);

            let pwd = pwd.clone();
            let encrypt_method = method;
            // let dnscache = dnscache_arc.clone();

            thread::spawn(move || {
                let remote_iv = {
                    let mut iv = Vec::with_capacity(encrypt_method.block_size());
                    stream.try_clone()
                          .unwrap()
                          .take(encrypt_method.block_size() as u64)
                          .read_to_end(&mut iv)
                          .unwrap();
                    iv
                };
                let decryptor = cipher::with_type(encrypt_method,
                                                  &pwd[..],
                                                  &remote_iv[..],
                                                  CryptoMode::Decrypt);

                let buffered_client_stream = BufStream::new(stream.try_clone().unwrap());
                let mut decrypt_stream = DecryptedReader::new(buffered_client_stream, decryptor);

                let addr = socks5::Address::read_from(&mut decrypt_stream).unwrap_or_else(|err| {
                    panic!("Error occurs while parsing request header, maybe wrong crypto method or password: {}",
                           err);
                });

                info!("Connecting to {}", addr);
                let remote_stream = TcpStream::connect(&addr).unwrap_or_else(|err| {
                    panic!("Unable to connect {:?}: {}", addr, err);
                });

                let mut remote_stream_cloned = remote_stream.try_clone().unwrap();
                let addr_cloned = addr.clone();
                Builder::new()
                    .name(format!("TCP relay from {:?} (local) to {:?}", stream.peer_addr().unwrap(), addr))
                    .spawn(move || {

                        match io::copy(&mut decrypt_stream, &mut remote_stream_cloned) {
                            Ok(n) => {
                                debug!("Relayed {} bytes from {} to {}",
                                       n,
                                       decrypt_stream.get_mut().get_mut().peer_addr().unwrap(),
                                       remote_stream_cloned.peer_addr().unwrap());
                            },
                            Err(err) => {
                                match err.kind() {
                                    ErrorKind::BrokenPipe => {
                                        debug!("{} relay from local to remote stream: {}", addr_cloned, err)
                                    },
                                    _ => {
                                        error!("{} relay from local to remote stream: {}", addr_cloned, err)
                                    }
                                }
                                let _ = remote_stream_cloned.shutdown(Shutdown::Write);
                                let _ = decrypt_stream.get_mut().get_mut().shutdown(Shutdown::Write);
                            }
                        }
                    }).unwrap();

                Builder::new()
                    .name(format!("TCP relay from {:?} (local) to {:?}", stream.peer_addr().unwrap(), addr))
                    .spawn(move|| {

                        let iv = encrypt_method.gen_init_vec();
                        let encryptor = cipher::with_type(encrypt_method,
                                                          &pwd[..],
                                                          &iv[..],
                                                          CryptoMode::Encrypt);
                        stream.write_all(&iv[..]).unwrap();
                        let mut buffered_remote_stream = BufStream::new(remote_stream);
                        let mut encrypt_stream = EncryptedWriter::new(stream, encryptor);
                        match io::copy(&mut buffered_remote_stream, &mut encrypt_stream) {
                            Ok(n) => {
                                debug!("Relayed {} bytes from {} to {}",
                                       n,
                                       buffered_remote_stream.get_mut().peer_addr().unwrap(),
                                       encrypt_stream.get_mut().peer_addr().unwrap());
                            },
                            Err(err) => {
                                match err.kind() {
                                    ErrorKind::BrokenPipe => {
                                        debug!("{} relay from remote to local stream: {}", addr, err)
                                    },
                                    _ => {
                                        error!("{} relay from remote to local stream: {}", addr, err)
                                    }
                                }
                                let _ = encrypt_stream.get_mut().shutdown(Shutdown::Write);
                                let _ = buffered_remote_stream.get_mut().shutdown(Shutdown::Write);
                            }
                        }
                    }).unwrap();
            });
        }
    }
}

impl Relay for TcpRelayServer {
    fn run(&self) {
        let mut threads = Vec::new();
        for s in self.config.server.iter() {
            let s = s.clone();
            let fut = thread::Builder::new().name(format!("TCP relay of `{}:{}`", s.addr, s.port)).spawn(move || {
                TcpRelayServer::accept_loop(s);
            }).unwrap();
            threads.push(fut);
        }

        for fut in threads.into_iter() {
            fut.join().unwrap();
        }
    }
}
