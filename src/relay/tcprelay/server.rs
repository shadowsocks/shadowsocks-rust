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
use std::task::try_future;
use std::io::{Listener, TcpListener, Acceptor, TcpStream};
use std::io::{EndOfFile, BrokenPipe};
use std::io::net::ip::SocketAddr;
use std::io::{BufReader, mod};
use std::time::duration::Duration;

use config::{Config, ServerConfig};
use relay::Relay;
use relay::socks5::{SocketAddress, DomainNameAddress, mod};
use relay::tcprelay::cached_dns::CachedDns;
use relay::tcprelay::relay_and_map;
use crypto::cipher;
use crypto::cipher::Cipher;

macro_rules! try_result(
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
)

#[deriving(Clone)]
pub struct TcpRelayServer {
    config: Config,
}

impl TcpRelayServer {
    pub fn new(c: Config) -> TcpRelayServer {
        if c.server.is_none() {
            panic!("You have to provide a server configuration");
        }
        TcpRelayServer {
            config: c,
        }
    }

    fn accept_loop(s: &ServerConfig) {
        let (server_addr, password, encrypt_method, timeout, dns_cache_capacity) =
                (s.addr,
                 Arc::new(s.password.clone()),
                 Arc::new(s.method.clone()),
                 s.timeout,
                 s.dns_cache_capacity);

        let mut acceptor = try_result!(TcpListener::bind(format!("{}:{}", server_addr.ip,
                                                         server_addr.port).as_slice()).listen(),
                                       prefix: "Failed to bind: ");

        info!("Shadowsocks listening on {}", server_addr);

        let dnscache_arc = Arc::new(CachedDns::new(dns_cache_capacity));

        for s in acceptor.incoming() {
            let mut stream = s.unwrap();
            stream.set_timeout(timeout);

            let password = password.clone();
            let encrypt_method = encrypt_method.clone();
            let dnscache = dnscache_arc.clone();

            spawn(proc() {
                let mut cipher = cipher::with_name(encrypt_method.as_slice(),
                                               password.as_slice().as_bytes())
                                        .expect("Unsupported cipher");

                let header = {
                    let mut buf = [0u8, .. 1024];
                    let header_len = try_result!(stream.read(buf), prefix: "Error occurs while reading header: ");
                    cipher.decrypt(buf.slice_to(header_len))
                };

                let mut bufr = BufReader::new(header.as_slice());
                let addr = try_result!(socks5::Address::read_from(&mut bufr),
                     prefix: "Error occurs while parsing request header, maybe wrong crypto method or password: "
                );

                info!("Connecting to {}", addr);
                let mut remote_stream = match addr {
                    SocketAddress(ip, port) => {
                        try_result!(TcpStream::connect_timeout(SocketAddr {ip: ip, port: port}, Duration::seconds(30)),
                                prefix: format!("Unable to connect {}:", addr)
                        )
                    },
                    DomainNameAddress(ref name, ref port) => {
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

                        let connector = || {
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

                        // TcpStream::connect(domainaddr.domain_name.as_slice(), domainaddr.port)
                        //     .ok().expect(format!("Unable to connect {}", domainaddr).as_slice())
                    }
                };

                // Fixed issue #3
                io::util::copy(&mut bufr, &mut remote_stream).unwrap();

                let mut remote_local_stream = stream.clone();
                let mut remote_remote_stream = remote_stream.clone();
                let mut remote_cipher = cipher.clone();
                let remote_addr_clone = addr.clone();
                spawn(proc() {
                    relay_and_map(&mut remote_remote_stream, &mut remote_local_stream,
                                  |msg| remote_cipher.encrypt(msg))
                        .unwrap_or_else(|err| {
                            match err.kind {
                                EndOfFile | BrokenPipe => {
                                    debug!("{} relay from remote to local stream: {}", remote_addr_clone, err)
                                },
                                _ => {
                                    error!("{} relay from remote to local stream: {}", remote_addr_clone, err)
                                }
                            }
                            remote_local_stream.close_write().or(Ok(())).unwrap();
                            remote_remote_stream.close_read().or(Ok(())).unwrap();
                        })
                });

                spawn(proc() {
                    relay_and_map(&mut stream, &mut remote_stream, |msg| cipher.decrypt(msg))
                        .unwrap_or_else(|err| {
                            match err.kind {
                                EndOfFile | BrokenPipe => {
                                    debug!("{} relay from local to remote stream: {}", addr, err)
                                },
                                _ => {
                                    error!("{} relay from local to remote stream: {}", addr, err)
                                }
                            }
                            remote_stream.close_write().or(Ok(())).unwrap();
                            stream.close_read().or(Ok(())).unwrap();
                        })
                });
            });
        }
    }
}

impl Relay for TcpRelayServer {
    fn run(&self) {
        let mut futures = Vec::new();
        for ref_s in self.config.server.as_ref().unwrap().iter() {
            let s = ref_s.clone();
            let fut = try_future(proc() {
                TcpRelayServer::accept_loop(&s);
            });
            futures.push(fut);
        }

        for fut in futures.into_iter() {
            drop(fut.unwrap());
        }
    }
}
