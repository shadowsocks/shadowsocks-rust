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

use std::task::try_future;
use std::sync::{Arc, Mutex};
use std::io::net::udp::UdpSocket;
use std::io::net::ip::SocketAddr;
use std::io::net::addrinfo::get_host_addresses;
use std::io::{MemWriter, BufReader};
use std::collections::LruCache;

use config::{Config, ServerConfig};
use relay::Relay;
use relay::socks5::{Address, mod};
use relay::udprelay::{UDP_RELAY_SERVER_LRU_CACHE_CAPACITY};
use crypto::cipher;
use crypto::cipher::Cipher;

#[deriving(Clone)]
pub struct UdpRelayServer {
    config: Config
}

impl UdpRelayServer {
    pub fn new(config: Config) -> UdpRelayServer {
        UdpRelayServer {
            config: config
        }
    }

    fn accept_loop(svr_config: &ServerConfig) {
        let mut socket = UdpSocket::bind(svr_config.addr).ok().expect("Unable to bind UDP socket");
        debug!("UDP server is binding {}", svr_config.addr);

        let client_map_arc = Arc::new(Mutex::new(
                            LruCache::<Address, SocketAddr>::new(UDP_RELAY_SERVER_LRU_CACHE_CAPACITY)));
        let remote_map_arc = Arc::new(Mutex::new(
                            LruCache::<SocketAddr, Address>::new(UDP_RELAY_SERVER_LRU_CACHE_CAPACITY)));

        let mut buf = [0u8, ..0xffff];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let data = buf.slice_to(len).to_vec();
                    let client_map = client_map_arc.clone();
                    let remote_map = remote_map_arc.clone();
                    let mut cipher = cipher::with_name(svr_config.method.as_slice(),
                                                       svr_config.password.as_slice().as_bytes())
                                            .expect("Unsupported cipher");
                    let mut captured_socket = socket.clone();

                    spawn(proc() {
                        match remote_map.lock().get(&src) {
                            Some(remote_addr) => {
                                match client_map.lock().get(remote_addr) {
                                    Some(client_addr) => {
                                        debug!("UDP response {} -> {}", remote_addr, client_addr);

                                        // Make a header
                                        let mut response_buf = MemWriter::new();
                                        remote_addr.write_to(&mut response_buf).unwrap();

                                        response_buf.write(data.as_slice()).unwrap();
                                        let encrypted_data = cipher.encrypt(response_buf.unwrap().as_slice());

                                        captured_socket
                                            .send_to(encrypted_data.as_slice(), client_addr.clone())
                                            .unwrap();
                                    },
                                    None => {
                                        // Unknown response, drop it.
                                    }
                                }

                                return;
                            },
                            None => {}
                        }

                        // Maybe data from a relay client
                        // Decrypt it and see what's inside
                        let decrypted_data = cipher.decrypt(data.as_slice());
                        let mut bufr = BufReader::new(decrypted_data.as_slice());

                        let header = socks5::UdpAssociateHeader::read_from(&mut bufr).unwrap();

                        if header.frag != 0 {
                            // Drop it
                            return;
                        }

                        info!("UDP ASSOCIATE {}", header.address);
                        debug!("UDP request {} -> {}", src, header.address);

                        let sockaddr = match &header.address {
                            &Address::SocketAddress(ip, port) => {
                                client_map.lock().insert(header.address.clone(), src);
                                remote_map.lock().insert(SocketAddr {ip: ip, port: port}, header.address.clone());
                                SocketAddr {ip: ip, port: port}
                            },
                            &Address::DomainNameAddress(ref dnaddr, port) => {
                                let ref ipaddrs = get_host_addresses(dnaddr.as_slice())
                                    .unwrap_or_else(|err| {
                                        panic!("Unable to resolve {}: {}", dnaddr, err);
                                    });

                                let remote_addr = SocketAddr {
                                                      ip: ipaddrs.head().unwrap().clone(),
                                                      port: port,
                                                  };
                                client_map.lock().insert(header.address.clone(), src);
                                remote_map.lock().insert(remote_addr, header.address.clone());
                                remote_addr
                            }
                        };
                        captured_socket.send_to(decrypted_data.as_slice().slice_from(header.len()), sockaddr).unwrap();
                    });
                },
                Err(err) => {
                    error!("Error occurs while calling recv_from: {}", err);
                    break;
                }
            }
        }
    }
}

impl Relay for UdpRelayServer {
    fn run(&self) {
        let mut futures = Vec::new();
        for sref in self.config.server.as_ref().unwrap().iter() {
            let s = sref.clone();
            let fut = try_future(proc() UdpRelayServer::accept_loop(&s));
            futures.push(fut);
        }

        for fut in futures.into_iter() {
            drop(fut.unwrap());
        }
    }
}
