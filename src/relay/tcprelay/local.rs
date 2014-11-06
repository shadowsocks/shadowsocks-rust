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

//! TcpRelay server that running on local environment

use std::io::{Listener, TcpListener, Acceptor, TcpStream};
use std::io::{
    EndOfFile,
    ConnectionFailed,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    BrokenPipe
};
use std::io::net::ip::SocketAddr;
use std::io::{MemWriter, BufferedStream};

use config::Config;

use relay::Relay;
use relay::socks5;
use relay::tcprelay::relay_and_map;
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};

use crypto::cipher;
use crypto::cipher::Cipher;

#[deriving(Clone)]
pub struct TcpRelayLocal {
    config: Config,
}

impl TcpRelayLocal {
    pub fn new(c: Config) -> TcpRelayLocal {
        if c.server.is_none() || c.local.is_none() {
            panic!("You have to provide configuration for server and local");
        }

        TcpRelayLocal {
            config: c,
        }
    }

    fn do_handshake(stream: &mut TcpStream) {
        // Read the handshake header
        let req = socks5::HandshakeRequest::read_from(stream).unwrap();

        if !req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
            let resp = socks5::HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
            resp.write_to(stream).unwrap();
            panic!("Currently shadowsocks-rust does not support authentication");
        }

        // Reply to client
        let resp = socks5::HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
        resp.write_to(stream).ok().expect("Error occurs while sending handshake reply");
    }

    fn handle_udp_associate_local(stream: &mut TcpStream, _: &socks5::Address) {
        let sockname = stream.socket_name().ok().expect("Failed to get socket name");

        let reply = socks5::TcpResponseHeader::new(socks5::Succeeded,
                                                   socks5::SocketAddress(sockname.ip, sockname.port));
        reply.write_to(stream).unwrap();

        // TODO: record this client's information for udprelay local server to validate
        //       whether the client has already authenticated
    }

    fn handle_client(mut stream: TcpStream,
                     server_addr: SocketAddr,
                     password: String,
                     encrypt_method: String,
                     enable_udp: bool) {
        TcpRelayLocal::do_handshake(&mut stream);

        let sockname = stream.socket_name().ok().expect("Failed to get socket name");

        let header = socks5::TcpRequestHeader::read_from(&mut stream).unwrap_or_else(|err| {
            socks5::TcpResponseHeader::new(err.reply,
                                           socks5::SocketAddress(sockname.ip, sockname.port));
            panic!("Failed to read request header: {}", err);
        });

        let addr = header.address;

        match header.command {
            socks5::TcpConnect => {
                info!("CONNECT {}", addr);

                let mut remote_stream = TcpStream::connect(
                            format!("{}:{}", server_addr.ip, server_addr.port).as_slice())
                    .unwrap_or_else(|err| {
                        match err.kind {
                            ConnectionAborted | ConnectionReset | ConnectionRefused | ConnectionFailed => {
                                socks5::TcpResponseHeader::new(socks5::HostUnreachable, addr.clone())
                                    .write_to(&mut stream).unwrap();
                            },
                            _ => {
                                socks5::TcpResponseHeader::new(socks5::NetworkUnreachable, addr.clone())
                                    .write_to(&mut stream).unwrap();
                            }
                        }
                        panic!("Failed to connect remote server: {}", err);
                    });

                let mut cipher = cipher::with_name(encrypt_method.as_slice(),
                                               password.as_slice().as_bytes())
                                        .expect("Unsupported cipher");

                stream = {
                    let mut buffered_stream = BufferedStream::new(stream);

                    socks5::TcpResponseHeader::new(socks5::Succeeded,
                                                   socks5::SocketAddress(sockname.ip, sockname.port))
                        .write_to(&mut buffered_stream).unwrap_or_else(|err| {
                            panic!("Error occurs while writing header to local stream: {}", err);
                        });
                    buffered_stream.flush().unwrap();

                    let mut header_buf = MemWriter::new();
                    addr.write_to(&mut header_buf).unwrap();

                    let encrypted_header = cipher.encrypt(header_buf.unwrap().as_slice());
                    remote_stream.write(encrypted_header.as_slice())
                            .ok().expect("Error occurs while writing header to remote stream");
                    buffered_stream.unwrap()
                };

                let mut remote_local_stream = stream.clone();
                let mut remote_remote_stream = remote_stream.clone();
                let mut remote_cipher = cipher.clone();
                let remote_addr_clone = addr.clone();
                spawn(proc() {
                    relay_and_map(&mut remote_remote_stream, &mut remote_local_stream,
                                  |msg| remote_cipher.decrypt(msg))
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
                    relay_and_map(&mut stream, &mut remote_stream, |msg| cipher.encrypt(msg))
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
            },
            socks5::TcpBind => {
                warn!("BIND is not supported");
                socks5::TcpResponseHeader::new(socks5::CommandNotSupported, addr)
                    .write_to(&mut stream).unwrap();
            },
            socks5::UdpAssociate => {
                let sockname = stream.peer_name().unwrap();
                info!("{} requests for UDP ASSOCIATE", sockname);
                if cfg!(feature = "enable-udp") && enable_udp {
                    TcpRelayLocal::handle_udp_associate_local(&mut stream, &addr);
                } else {
                    warn!("UDP ASSOCIATE is disabled");
                    socks5::TcpResponseHeader::new(socks5::CommandNotSupported, addr)
                        .write_to(&mut stream).unwrap();
                }
            }
        }
    }
}

impl Relay for TcpRelayLocal {
    fn run(&self) {
        let mut server_load_balancer = RoundRobin::new(
                                        self.config.server.clone().expect("`server` should not be None"));

        let local_conf = self.config.local.unwrap();

        let mut acceptor = match TcpListener::bind(
                format!("{}:{}", local_conf.ip, local_conf.port).as_slice()).listen() {
            Ok(acpt) => acpt,
            Err(e) => {
                panic!("Error occurs while listening local address: {}", e.to_string());
            }
        };

        info!("Shadowsocks listening on {}", local_conf);

        for s in acceptor.incoming() {
            let stream = s.unwrap();

            let (server_addr, password, encrypt_method) = {
                let ref s = server_load_balancer.pick_server();
                (s.addr.clone(), s.password.clone(), s.method.clone())
            };

            let enable_udp = self.config.enable_udp;
            spawn(proc()
                TcpRelayLocal::handle_client(stream,
                                             server_addr,
                                             password,
                                             encrypt_method,
                                             enable_udp));
        }
    }
}
