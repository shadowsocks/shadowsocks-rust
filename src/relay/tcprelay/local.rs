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

/* code */

#[phase(plugin, link)]
extern crate log;
// extern crate native;

use std::sync::Arc;
use std::io::{Listener, TcpListener, Acceptor, TcpStream};
use std::io::{EndOfFile, TimedOut, NotConnected};
use std::io::net::ip::Port;

use config::Config;

use relay::Relay;
use relay::{parse_request_header, send_error_reply};
use relay::{SOCK5_VERSION, SOCK5_AUTH_METHOD_NONE};
use relay::{SOCK5_CMD_TCP_CONNECT, SOCK5_CMD_TCP_BIND, SOCK5_CMD_UDP_ASSOCIATE};
use relay::{SOCK5_REPLY_COMMAND_NOT_SUPPORTED};
use relay::SOCK5_REPLY_SUCCEEDED;

use crypto::cipher;
use crypto::cipher::CipherVariant;
use crypto::cipher::Cipher;

pub struct TcpRelayLocal {
    config: Config,
}

impl TcpRelayLocal {
    pub fn new(c: Config) -> TcpRelayLocal {
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

        if sock_ver != SOCK5_VERSION {
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
        let data_to_send: &[u8] = [SOCK5_VERSION, SOCK5_AUTH_METHOD_NONE];
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
                     server_addr: Arc<String>, server_port: Arc<Port>,
                     password: Arc<String>, encrypt_method: Arc<String>) {
        TcpRelayLocal::do_handshake(stream);

        let raw_header_part1 = stream.read_exact(3)
                                        .ok().expect("Error occurs while reading request header");
        let (sock_ver, cmd) = (raw_header_part1[0], raw_header_part1[1]);

        if sock_ver != SOCK5_VERSION {
            fail!("Invalid sock version {}", sock_ver);
        }

        let (header, addr) = {
            let mut header_buf = [0u8, .. 512];
            stream.read_at_least(1, header_buf)
                        .ok().expect("Error occurs while reading header");

            let (header_len, addr)
                    = parse_request_header(stream, header_buf);
            (header_buf.slice_to(header_len).to_vec(), addr)
        };

        let mut remote_stream = TcpStream::connect(server_addr.as_slice(),
                                           *server_port.deref())
                        .ok().expect("Error occurs while connecting to remote server");

        let mut cipher = cipher::with_name(encrypt_method.as_slice(),
                                       password.as_slice().as_bytes())
                                .expect("Unsupported cipher");

        match cmd {
            SOCK5_CMD_TCP_CONNECT => {
                info!("CONNECT {}", addr);

                {
                    let reply = [SOCK5_VERSION, SOCK5_REPLY_SUCCEEDED,
                                    0x00, SOCK5_CMD_TCP_CONNECT, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10];
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

                TcpRelayLocal::handle_connect_local(stream,
                                                    &mut remote_stream,
                                                    &mut cipher);
            },
            SOCK5_CMD_TCP_BIND => {
                unimplemented!();
            },
            SOCK5_CMD_UDP_ASSOCIATE => {
                unimplemented!();
            },
            _ => {
                // unsupported CMD
                send_error_reply(stream, SOCK5_REPLY_COMMAND_NOT_SUPPORTED);
                fail!("Unsupported command");
            }
        }

        drop(stream);
        drop(remote_stream);
    }
}

impl Relay for TcpRelayLocal {
    fn run(&self) {
        let local_addr = self.config.local.as_slice();
        let local_port = self.config.local_port;

        let server_addr = Arc::new(self.config.server.clone());
        let server_port = Arc::new(self.config.server_port);

        let password = Arc::new(self.config.password.clone());
        let encrypt_method = Arc::new(self.config.method.clone());

        let timeout = match self.config.timeout {
            Some(timeout) => Some(timeout * 1000),
            None => None
        };

        let mut acceptor = match TcpListener::bind(local_addr, local_port).listen() {
            Ok(acpt) => acpt,
            Err(e) => {
                fail!("Error occurs while listening local address: {}", e.to_string());
            }
        };

        info!("Shadowsocks listening on {}:{}", local_addr, local_port);

        loop {
            match acceptor.accept() {
                Ok(mut stream) => {
                    stream.set_timeout(timeout);

                    let server_addr = server_addr.clone();
                    let server_port = server_port.clone();

                    let password = password.clone();
                    let encrypt_method = encrypt_method.clone();

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
