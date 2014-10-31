// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

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
use std::io::{EndOfFile, TimedOut, BrokenPipe};
use std::io::net::ip::SocketAddr;
use std::time::duration::Duration;

use config::{Config, SingleServer, MultipleServer, ServerConfig};
use relay::Relay;
use relay::socks5::{parse_request_header, SocketAddress, DomainNameAddress};
use relay::tcprelay::cached_dns::CachedDns;
use crypto::cipher;
use crypto::cipher::Cipher;
use crypto::cipher::CipherVariant;

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

    fn handle_connect_remote(local_stream: &mut TcpStream, remote_stream: &mut TcpStream,
                                          cipher: &mut CipherVariant) {
        let mut buf = [0u8, .. 0xffff];

        loop {
            match remote_stream.read_at_least(1, buf) {
                Ok(len) => {
                    let real_buf = buf.slice_to(len);

                    let encrypted_msg = cipher.encrypt(real_buf);

                    match local_stream.write(encrypted_msg.as_slice()) {
                        Ok(..) => {},
                        Err(err) => {
                            match err.kind {
                                EndOfFile | TimedOut | BrokenPipe => {},
                                _ => {
                                    error!("Error occurs while writing to local stream: {}", err);
                                }
                            }
                            remote_stream.close_read().unwrap();
                            break
                        }
                    }
                },
                Err(err) => {
                    match err.kind {
                        EndOfFile | TimedOut | BrokenPipe => {},
                        _ => {
                            error!("Error occurs while reading from remote stream: {}", err);
                        }
                    }
                    local_stream.close_write().unwrap();
                    break
                }
            }
        }
    }

    fn handle_connect_local(local_stream: &mut TcpStream, remote_stream: &mut TcpStream,
                            cipher: &mut CipherVariant) {
        let mut buf = [0u8, .. 0xffff];
        loop {
            match local_stream.read(buf) {
                Ok(len) => {
                    let real_buf = buf.slice_to(len);
                    let decrypted_msg = cipher.decrypt(real_buf);
                    match remote_stream.write(decrypted_msg.as_slice()) {
                        Ok(..) => {},
                        Err(err) => {
                            error!("Error occurs while writing to remote stream: {}", err);
                            local_stream.close_read().unwrap();
                        }
                    }
                },
                Err(err) => {
                    match err.kind {
                        EndOfFile | TimedOut | BrokenPipe => {},
                        _ => {
                            error!("Error occurs while reading from client stream: {}", err);
                        }
                    }
                    remote_stream.close_write().unwrap();
                    break
                }
            }
        }
    }

    fn accept_loop(s: &ServerConfig) {
        let (server_addr, server_port, password, encrypt_method, timeout, dns_cache_capacity) =
                (s.address.to_string(),
                 s.port,
                 Arc::new(s.password.clone()),
                 Arc::new(s.method.clone()),
                 s.timeout,
                 s.dns_cache_capacity);

        let mut acceptor = match TcpListener::bind(server_addr.as_slice(), server_port).listen() {
            Ok(acpt) => acpt,
            Err(e) => {
                panic!("Binding server address: {}", e.to_string());
            }
        };

        info!("Shadowsocks listening on {}:{}", server_addr, server_port);

        let dnscache_arc = Arc::new(CachedDns::new(dns_cache_capacity));

        loop {
            match acceptor.accept() {
                Ok(mut stream) => {
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
                            let header_len = stream.read(buf).ok()
                                                    .expect("Error occurs while reading header");
                            let encrypted_header = buf.slice_to(header_len);
                            cipher.decrypt(encrypted_header)
                        };

                        let (_, addr) = match parse_request_header(header.as_slice()) {
                            Ok((header_len, addr)) => (header_len, addr),
                            Err(..) => {
                                panic!("Error occurs while parsing request header, \
                                            maybe wrong crypto method or password");
                            }
                        };
                        info!("Connecting to {}", addr);
                        let mut remote_stream = match addr {
                            SocketAddress(sockaddr) => {
                                match TcpStream::connect_timeout(sockaddr, Duration::seconds(30)) {
                                    Ok(s) => s,
                                    Err(err) => {
                                        panic!("Unable to connect {}: {}", sockaddr, err)
                                    }
                                }
                            },
                            DomainNameAddress(ref domainaddr) => {
                                let ipaddrs = {
                                    // Cannot fail inside, which will cause other tasks fail, too.
                                    dnscache.resolve(domainaddr.domain_name.as_slice())
                                };

                                match ipaddrs {
                                    Some(ipaddrs) => {
                                        let connect_host = || {
                                            for ipaddr in ipaddrs.iter() {
                                                match TcpStream::connect_timeout(SocketAddr {ip: *ipaddr,
                                                        port: domainaddr.port}, Duration::seconds(30)) {
                                                    Ok(stream) => return stream,
                                                    Err(err) => {
                                                        debug!("Connecting {}: {} failed", ipaddr, err);
                                                    },
                                                }
                                            }
                                            panic!("Unable to connect {}", domainaddr);
                                        };
                                        connect_host()
                                    },

                                    None => {
                                        panic!("Failed to resolve {}", domainaddr);
                                    }
                                }
                            }
                        };

                        let mut remote_local_stream = stream.clone();
                        let mut remote_remote_stream = remote_stream.clone();
                        let mut remote_cipher = cipher.clone();
                        spawn(proc()
                            TcpRelayServer::handle_connect_remote(&mut remote_local_stream,
                                                                  &mut remote_remote_stream,
                                                                  &mut remote_cipher));
                        spawn(proc()
                            TcpRelayServer::handle_connect_local(&mut stream,
                                                                 &mut remote_stream,
                                                                 &mut cipher));
                    });
                },
                Err(e) => {
                    panic!("Error occurs while accepting: {}", e.to_string());
                }
            }
        }
    }
}

impl Relay for TcpRelayServer {
    fn run(&self) {
        let mut futures = Vec::new();
        match self.config.server.clone().unwrap() {
            SingleServer(s) => {
                let fut = try_future(proc() {
                    TcpRelayServer::accept_loop(&s);
                });
                futures.push(fut);
            },
            MultipleServer(slist) => {
                for ref_s in slist.iter() {
                    let s = ref_s.clone();
                    let fut = try_future(proc() {
                        TcpRelayServer::accept_loop(&s);
                    });
                    futures.push(fut);
                }
            }
        }

        for fut in futures.into_iter() {
            drop(fut);
        }
    }
}
