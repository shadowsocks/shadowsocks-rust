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

// SOCKS5 UDP Request
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// SOCKS5 UDP Response
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// shadowsocks UDP Request (before encrypted)
// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+

// shadowsocks UDP Response (before encrypted)
// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+

// shadowsocks UDP Request and Response (after encrypted)
// +-------+--------------+
// |   IV  |    PAYLOAD   |
// +-------+--------------+
// | Fixed |   Variable   |
// +-------+--------------+

#[phase(plugin, link)]
extern crate log;

use std::io::net::udp::UdpSocket;
use std::io::net::ip::SocketAddr;
use std::sync::Arc;
use std::collections::LruCache;

use config::Config;
use relay::Relay;
use relay::parse_request_header;
use crypto::cipher;
use crypto::cipher::Cipher;

const UDP_RELAY_LOCAL_LRU_CACHE_CAPACITY: uint = 100;

#[deriving(Clone)]
pub struct UdpRelayLocal {
    config: Config,
}

impl UdpRelayLocal {
    pub fn new(config: Config) -> UdpRelayLocal {
        UdpRelayLocal {
            config: config,
        }
    }

    fn handle_request(socket: UdpSocket, request_message: Vec<u8>, client_addr: SocketAddr, config: &Config) {
        // According to RFC 1928
        //
        // Implementation of fragmentation is optional; an implementation that
        // does not support fragmentation MUST drop any datagram whose FRAG
        // field is other than X'00'.
        if request_message[2] != 0x00u8 {
            // Drop it
            warn!("Does not support fragmentation");
            return;
        }

        let data = request_message.as_slice().slice_from(3);

        let (_, addr) = match parse_request_header(data) {
            Ok(result) => result,
            Err(..) => {
                error!("Error while parsing request header");
                return;
            }
        };

        info!("UDP_ASSOCIATE {}", addr);

        let mut cipher = cipher::with_name(config.method.as_slice(), config.password.as_slice().as_bytes())
                            .expect(format!("Unsupported cipher {}", config.method.as_slice()).as_slice());
        let encrypted_data = cipher.encrypt(data);

        let remote_addr = SocketAddr {
            ip: from_str(config.server.as_slice()).expect("Invalid server ip address"),
            port: config.server_port
        };

        let mut cloned_socket = socket.clone();
        let data_to_reply = {
            let mut remote_socket = socket.connect(remote_addr);
            remote_socket.write(encrypted_data.as_slice())
                .ok().expect("Error occurs while sending data to remote udp server");

            let mut buf = [0u8, .. 0xffff];
            match remote_socket.read_at_least(3, buf) {
                Ok(len) => {
                    let recv_msg = buf.slice_to(len);
                    let decrypted_msg = cipher.decrypt(recv_msg);

                    decrypted_msg
                },
                Err(err) => {
                    fail!("Error occurs while receiving from remote udp server: {}", err)
                }
            }
        };
        cloned_socket.send_to(data_to_reply.as_slice(), client_addr)
            .ok().expect("Error occurs while sending data to local udp client");
    }
}

impl Relay for UdpRelayLocal {
    fn run(&self) {
        let ref local_addr = self.config.local;
        let ref local_port = self.config.local_port;

        let addr = SocketAddr {ip: from_str(local_addr.as_slice()).expect("Invalid local ip address"),
                               port: *local_port};
        let mut socket = UdpSocket::bind(addr).ok().expect("Failed to bind udp socket");

        let config_arc = Arc::new(self.config.clone());

        let mut buf = [0u8, .. 0xffff];
        loop {
            match socket.recv_from(buf) {
                Ok((len, source_addr)) => {
                    if len < 4 {
                        error!("UDP request header too short");
                        continue;
                    }

                    let request_message = buf.slice_to(len).to_vec();
                    let config = config_arc.clone();
                    let move_socket = socket.clone();
                    spawn(proc()
                            UdpRelayLocal::handle_request(move_socket, request_message, source_addr, config.deref()));
                },
                Err(err) => {
                    error!("Failed in UDP recv_from: {}", err);
                    break
                }
            }
        }
    }
}
