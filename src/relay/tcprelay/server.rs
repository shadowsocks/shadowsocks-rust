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
use std::io::{Listener, TcpListener, Acceptor, TcpStream};
use std::io::{EndOfFile, BrokenPipe};
use std::io::net::ip::SocketAddr;
use std::io::{BufferedStream, self};
use std::time::duration::Duration;
use std::thread::Thread;

use config::{Config, ServerConfig};
use relay::Relay;
use relay::socks5::{Address, self};
use relay::tcprelay::cached_dns::CachedDns;
use relay::tcprelay::stream::{DecryptedReader, EncryptedWriter};
use crypto::cipher;
use crypto::CryptoMode;

macro_rules! try_result{
    ($res:expr) => ({
        let res = $res;
        match res {
            Ok(r) => { r },
            Err(err) => {
                error!("{}", err);
                return;
            }
        }
    });
    ($res:expr, prefix: $prefix:expr) => ({
        let res = $res;
        let prefix = $prefix;
        match res {
            Ok(r) => { r },
            Err(err) => {
                error!("{} {}", prefix, err);
                return;
            }
        }
    });
    ($res:expr, message: $message:expr) => ({
        let res = $res;
        let message = $message;
        match res {
            Ok(r) => { r },
            Err(..) => {
                error!("{}", message);
                return;
            }
        }
    });
}

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
        let mut acceptor = try_result!(TcpListener::bind((s.addr.as_slice(), s.port)).listen(),
                                       prefix: "Failed to bind: ");

        info!("Shadowsocks listening on {}", s.addr);

        let dnscache_arc = Arc::new(CachedDns::with_capacity(s.dns_cache_capacity));

        let pwd = s.method.bytes_to_key(s.password.as_bytes());
        let timeout = s.timeout;
        let method = s.method;
        for s in acceptor.incoming() {
            let mut stream = s.unwrap();
            stream.set_timeout(timeout);

            let pwd = pwd.clone();
            let encrypt_method = method;
            let dnscache = dnscache_arc.clone();

            Thread::spawn(move || {
                let remote_iv = try_result!(stream.read_exact(encrypt_method.block_size()));
                let decryptor = cipher::with_type(encrypt_method,
                                                  pwd.as_slice(),
                                                  remote_iv.as_slice(),
                                                  CryptoMode::Decrypt);

                let buffered_client_stream = BufferedStream::new(stream.clone());
                let mut decrypt_stream = DecryptedReader::new(buffered_client_stream, decryptor);

                let addr = try_result!(socks5::Address::read_from(&mut decrypt_stream),
                     prefix: "Error occurs while parsing request header, maybe wrong crypto method or password: "
                );

                info!("Connecting to {}", addr);
                let mut remote_stream = match addr {
                    Address::SocketAddress(ip, port) => {
                        try_result!(TcpStream::connect_timeout(SocketAddr {ip: ip, port: port}, Duration::seconds(30)),
                                prefix: format!("Unable to connect {}:", addr)
                        )
                    },
                    Address::DomainNameAddress(ref name, ref port) => {
                        let ipaddrs = {
                            // Cannot fail inside, which will cause other tasks fail, too.
                            match dnscache.resolve(name.as_slice()) {
                                Some(v) => { v },
                                None => {
                                    error!("Unable to resolve {}:{}", name, port);
                                    return;
                                }
                            }
                        };

                        let connector = |&:| {
                            for ipaddr in ipaddrs.iter() {
                                let result = TcpStream::connect_timeout(SocketAddr {
                                                                ip: *ipaddr,
                                                                port: *port
                                                            },
                                                            Duration::seconds(30));
                                match result {
                                    Err(err) => debug!("{} trying {}: {}", addr, ipaddr, err),
                                    Ok(host) => {
                                        debug!("{} trying {}: succeed", addr, ipaddr);
                                        return host;
                                    }
                                }
                            }
                            panic!("Unable to connect {}", addr);
                        };
                        connector()
                    }
                };

                let mut remote_stream_cloned = remote_stream.clone();
                let addr_cloned = addr.clone();
                Thread::spawn(move || {
                    match io::util::copy(&mut decrypt_stream, &mut remote_stream_cloned) {
                        Ok(..) => {},
                        Err(err) => {
                            match err.kind {
                                EndOfFile | BrokenPipe => {
                                    debug!("{} relay from local to remote stream: {}", addr_cloned, err)
                                },
                                _ => {
                                    error!("{} relay from local to remote stream: {}", addr_cloned, err)
                                }
                            }
                            remote_stream_cloned.close_write().or(Ok(())).unwrap();
                            decrypt_stream.get_mut().get_mut().close_read().or(Ok(())).unwrap();
                        }
                    }
                });

                let iv = encrypt_method.gen_init_vec();
                let encryptor = cipher::with_type(encrypt_method,
                                                  pwd.as_slice(),
                                                  iv.as_slice(),
                                                  CryptoMode::Encrypt);
                try_result!(stream.write(iv.as_slice()));
                let mut buffered_remote_stream = BufferedStream::new(remote_stream.clone());
                let mut encrypt_stream = EncryptedWriter::new(stream.clone(), encryptor);
                match io::util::copy(&mut buffered_remote_stream, &mut encrypt_stream) {
                    Ok(..) => {},
                    Err(err) => {
                        match err.kind {
                            EndOfFile | BrokenPipe => {
                                debug!("{} relay from remote to local stream: {}", addr, err)
                            },
                            _ => {
                                error!("{} relay from remote to local stream: {}", addr, err)
                            }
                        }
                        encrypt_stream.get_mut().close_write().or(Ok(())).unwrap();
                        buffered_remote_stream.get_mut().close_read().or(Ok(())).unwrap();
                    }
                }
            });
        }
    }
}

impl Relay for TcpRelayServer {
    fn run(&self) {
        let mut threads = Vec::new();
        for s in self.config.server.iter() {
            let s = s.clone();
            let fut = Thread::scoped(move || {
                TcpRelayServer::accept_loop(s);
            });
            threads.push(fut);
        }

        for fut in threads.into_iter() {
            fut.join().ok().expect("A thread failed and exited");
        }
    }
}
