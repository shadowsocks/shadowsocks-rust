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

//! TcpRelay server that running on local environment

#[phase(plugin, link)]
extern crate log;
// extern crate native;

use std::sync::Arc;
use std::io::{Listener, TcpListener, Acceptor, TcpStream};
use std::io::{EndOfFile, TimedOut, NotConnected};
use std::io::net::ip::Port;
use std::io::net::ip::{Ipv4Addr, Ipv6Addr};

use config::Config;

use relay::Relay;
use relay::{parse_request_header, send_error_reply};
use relay::{SOCKS5_VERSION, SOCKS5_AUTH_METHOD_NONE};
use relay::{SOCKS5_CMD_TCP_CONNECT, SOCKS5_CMD_TCP_BIND, SOCKS5_CMD_UDP_ASSOCIATE};
use relay::{SOCKS5_ADDR_TYPE_IPV6, SOCKS5_ADDR_TYPE_IPV4};
use relay::{SOCKS5_REPLY_COMMAND_NOT_SUPPORTED};
use relay::SOCKS5_REPLY_SUCCEEDED;
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};

use crypto::cipher;
use crypto::cipher::CipherVariant;
use crypto::cipher::Cipher;

#[deriving(Clone)]
pub struct TcpRelayLocal {
    config: Config,
}

impl TcpRelayLocal {
    pub fn new(c: Config) -> TcpRelayLocal {
        if c.server.is_none() || c.local.is_none() {
            fail!("You have to provide configuration for server and local");
        }
        TcpRelayLocal {
            config: c,
        }
    }

    fn do_handshake(stream: &mut TcpStream) {
        // Read the handshake header
        // +----+----------+----------+
        // |VER | NMETHODS | METHODS  |
        // +----+----------+----------+
        // | 5  |    1     | 1 to 255 |
        // +----+----------+----------+
        let handshake_header = stream.read_exact(2).ok().expect("Error occurs while receiving handshake header");
        let (sock_ver, nmethods) = (handshake_header[0], handshake_header[1]);

        if sock_ver != SOCKS5_VERSION {
            fail!("Invalid sock version {}", sock_ver);
        }

        let _ = stream.read_exact(nmethods as uint).ok().expect("Error occurs while receiving methods");
        // TODO: validating methods

        // Reply to client
        // +----+--------+
        // |VER | METHOD |
        // +----+--------+
        // | 1  |   1    |
        // +----+--------+
        let data_to_send: &[u8] = [SOCKS5_VERSION, SOCKS5_AUTH_METHOD_NONE];
        stream.write(data_to_send).ok().expect("Error occurs while sending handshake reply");
    }

    fn handle_connect_local(local_stream: &mut TcpStream, remote_stream: &mut TcpStream,
                                   cipher: &mut CipherVariant) {
        let mut buf = [0u8, .. 0xffff];

        loop {
            match local_stream.read_at_least(1, buf) {
                Ok(len) => {
                    let real_buf = buf.slice_to(len);

                    let encrypted_msg = cipher.encrypt(real_buf);
                    match remote_stream.write(encrypted_msg.as_slice()) {
                        Ok(..) => {},
                        Err(err) => {
                            match err.kind {
                                EndOfFile | TimedOut => {},
                                _ => {
                                    error!("Error occurs while writing to remote stream: {}", err);
                                }
                            }
                            match local_stream.close_read() {
                                Ok(..) => (),
                                Err(err) => {
                                    if err.kind != NotConnected {
                                        error!("Error occurs while closing local read: {}", err);
                                    }
                                }
                            }
                            break
                        }
                    }
                },
                Err(err) => {
                    match err.kind {
                        EndOfFile | TimedOut => {},
                        _ => {
                            error!("Error occurs while reading from local stream: {}", err);
                        }
                    }
                    match remote_stream.close_write() {
                        Ok(..) => (),
                        Err(err) => {
                            if err.kind != NotConnected {
                                error!("Error occurs while closing remote write: {}", err);
                            }
                        }
                    }
                    break
                }
            }
        }
    }

    fn handle_connect_remote(local_stream: &mut TcpStream, remote_stream: &mut TcpStream,
                                          cipher: &mut CipherVariant) {

        let mut buf = [0u8, .. 0xffff];

        loop {
            match remote_stream.read_at_least(1, buf) {
                Ok(len) => {
                    let real_buf = buf.slice_to(len);

                    let decrypted_msg = cipher.decrypt(real_buf);

                    // debug!("Recv from remote: {}", decrypted_msg);

                    match local_stream.write(decrypted_msg.as_slice()) {
                        Ok(..) => {},
                        Err(err) => {
                            match err.kind {
                                EndOfFile | TimedOut => {},
                                _ => {
                                    error!("Error occurs while writing to local stream: {}", err);
                                }
                            }
                            match remote_stream.close_read() {
                                Ok(..) => (),
                                Err(err) => {
                                    if err.kind != NotConnected {
                                        error!("Error occurs while closing remote read: {}", err);
                                    }
                                }
                            }
                            break
                        }
                    }
                },
                Err(err) => {
                    match err.kind {
                        EndOfFile | TimedOut => {},
                        _ => {
                            error!("Error occurs while reading from remote stream: {}", err);
                        }
                    }
                    match local_stream.close_write() {
                        Ok(..) => (),
                        Err(err) => {
                            if err.kind != NotConnected {
                                error!("Error occurs while closing remote write: {}", err);
                            }
                        }
                    }
                    break
                }
            }
        }
    }

    fn handle_client(stream: &mut TcpStream,
                     server_addr: String, server_port: Port,
                     password: String, encrypt_method: String) {
        TcpRelayLocal::do_handshake(stream);

        let raw_header_part1 = stream.read_exact(3)
                                        .ok().expect("Error occurs while reading request header");
        let (sock_ver, cmd) = (raw_header_part1[0], raw_header_part1[1]);

        if sock_ver != SOCKS5_VERSION {
            fail!("Invalid sock version {}", sock_ver);
        }

        let (header, addr) = {
            let mut header_buf = [0u8, .. 512];
            stream.read_at_least(1, header_buf)
                        .ok().expect("Error occurs while reading header");

            let (header_len, addr) = match parse_request_header(header_buf) {
                Ok((header_len, addr)) => (header_len, addr),
                Err(err_code) => {
                    send_error_reply(stream, err_code);
                    fail!("Error occurs while parsing request header");
                }
            };
            (header_buf.slice_to(header_len).to_vec(), addr)
        };

        let mut remote_stream = TcpStream::connect(server_addr.as_slice(),
                                           server_port)
                        .ok().expect("Error occurs while connecting to remote server");

        let mut cipher = cipher::with_name(encrypt_method.as_slice(),
                                       password.as_slice().as_bytes())
                                .expect("Unsupported cipher");

        match cmd {
            SOCKS5_CMD_TCP_CONNECT => {
                info!("CONNECT {}", addr);

                {
                    let reply = [SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED,
                                    0x00, SOCKS5_CMD_TCP_CONNECT, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10];
                    stream.write(reply)
                            .ok().expect("Error occurs while writing header to local stream");

                    let encrypted_header = cipher.encrypt(header.as_slice());
                    remote_stream.write(encrypted_header.as_slice())
                            .ok().expect("Error occurs while writing header to remote stream");
                }

                let mut remote_local_stream = stream.clone();
                let mut remote_remote_stream = remote_stream.clone();
                let mut remote_cipher = cipher.clone();
                spawn(proc()
                    TcpRelayLocal::handle_connect_remote(&mut remote_local_stream,
                                                         &mut remote_remote_stream,
                                                         &mut remote_cipher));

                let mut local_local_stream = stream.clone();
                spawn(proc()
                    TcpRelayLocal::handle_connect_local(&mut local_local_stream,
                                                        &mut remote_stream,
                                                        &mut cipher));
            },
            SOCKS5_CMD_TCP_BIND => {
                unimplemented!();
            },
            SOCKS5_CMD_UDP_ASSOCIATE => {
                info!("UDP ASSOCIATE {}", addr);

                let sockname = stream.socket_name().ok().expect("Failed to get socket name");
                let mut reply = vec![SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, 0x00,
                                SOCKS5_CMD_UDP_ASSOCIATE];
                match sockname.ip {
                    Ipv4Addr(v1, v2, v3, v4) => {
                        let ip = [v1, v2, v3, v4];
                        reply.push(SOCKS5_ADDR_TYPE_IPV4);
                        reply.push_all(ip)
                    },
                    Ipv6Addr(v1, v2, v3, v4, v5, v6, v7, v8) => {
                        let ip = [(v1 >> 8) as u8, (v1 & 0xff) as u8,
                         (v2 >> 8) as u8, (v2 & 0xff) as u8,
                         (v3 >> 8) as u8, (v3 & 0xff) as u8,
                         (v4 >> 8) as u8, (v4 & 0xff) as u8,
                         (v5 >> 8) as u8, (v5 & 0xff) as u8,
                         (v6 >> 8) as u8, (v6 & 0xff) as u8,
                         (v7 >> 8) as u8, (v7 & 0xff) as u8,
                         (v8 >> 8) as u8, (v8 & 0xff) as u8];
                        reply.push(SOCKS5_ADDR_TYPE_IPV6);
                        reply.push_all(ip);
                    }
                }

                reply.push((sockname.port >> 8) as u8);
                reply.push((sockname.port & 0xff) as u8);

                stream.write(reply.as_slice()).ok().expect("Failed to write to local stream");
            },
            _ => {
                // unsupported CMD
                send_error_reply(stream, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
                fail!("Unsupported command");
            }
        }
    }
}

impl Relay for TcpRelayLocal {
    fn run(&self) {
        let mut server_load_balancer = Arc::new(RoundRobin::new(self.config.clone()));

        let local_conf = self.config.local.unwrap();

        let mut acceptor = match TcpListener::bind(local_conf.ip.to_string().as_slice(), local_conf.port).listen() {
            Ok(acpt) => acpt,
            Err(e) => {
                fail!("Error occurs while listening local address: {}", e.to_string());
            }
        };

        info!("Shadowsocks listening on {}", local_conf);

        loop {
            match acceptor.accept() {
                Ok(mut stream) => {
                    let (server_addr, server_port, password, encrypt_method) = {
                        let slb = server_load_balancer.make_unique();
                        let ref s = slb.pick_server();
                        (s.address.clone(), s.port.clone(), s.password.clone(), s.method.clone())
                    };

                    spawn(proc()
                        TcpRelayLocal::handle_client(&mut stream,
                                                     server_addr, server_port,
                                                     password, encrypt_method));
                },
                Err(e) => {
                    fail!("Error occurs while accepting: {}", e.to_string());
                }
            }
        }
    }
}
