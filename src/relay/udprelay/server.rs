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

use std::sync::{Arc, Mutex};
use std::net::{UdpSocket, SocketAddr, SocketAddrV4, SocketAddrV6, lookup_host};
use std::io::{BufReader, Read};

use lru_cache::LruCache;

use coio::Builder;

use config::{Config, ServerConfig};
use relay::socks5::{Address, self};
use relay::COROUTINE_STACK_SIZE;
use relay::udprelay::{UDP_RELAY_SERVER_LRU_CACHE_CAPACITY};
use crypto::{cipher, CryptoMode};
use crypto::cipher::Cipher;

#[derive(Clone)]
pub struct UdpRelayServer {
    config: Config
}

impl UdpRelayServer {
    pub fn new(config: Config) -> UdpRelayServer {
        UdpRelayServer {
            config: config
        }
    }

    fn accept_loop(svr_config: ServerConfig) {
        let socket = UdpSocket::bind(&(&svr_config.addr[..], svr_config.port))
            .ok().expect("Unable to bind UDP socket");
        debug!("UDP server is binding {}", svr_config.addr);

        let client_map_arc = Arc::new(Mutex::new(
                            LruCache::<Address, SocketAddr>::new(UDP_RELAY_SERVER_LRU_CACHE_CAPACITY)));
        let remote_map_arc = Arc::new(Mutex::new(
                            LruCache::<SocketAddr, Address>::new(UDP_RELAY_SERVER_LRU_CACHE_CAPACITY)));

        let mut buf = [0u8; 0xffff];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let data = buf[..len].to_vec();
                    let client_map = client_map_arc.clone();
                    let remote_map = remote_map_arc.clone();
                    let captured_socket = match socket.try_clone() {
                        Ok(sk) => sk,
                        Err(err) => {
                            error!("Error occurs while cloning socket: {:?}", err);
                            return;
                        }
                    };

                    let method = svr_config.method;
                    let password = svr_config.password.clone();

                    Builder::new().stack_size(COROUTINE_STACK_SIZE).spawn(move || {
                        match remote_map.lock().unwrap().get(&src) {
                            Some(remote_addr) => {
                                match client_map.lock().unwrap().get(remote_addr) {
                                    Some(client_addr) => {
                                        debug!("UDP response {} -> {}", remote_addr, client_addr);

                                        // Make a header
                                        let mut response_buf = Vec::new();
                                        if let Err(err) = remote_addr.write_to(&mut response_buf) {
                                            error!("Error occurs while writing remote addr: {:?}", err);
                                            return;
                                        }

                                        response_buf.extend(&data[..]);

                                        let key = method.bytes_to_key(password.as_bytes());
                                        let mut iv = method.gen_init_vec();
                                        let mut encryptor =
                                            cipher::with_type(method,
                                                              &key[..],
                                                              &iv[..],
                                                              CryptoMode::Encrypt);

                                        if let Err(err) = encryptor.update(&response_buf[..], &mut iv) {
                                            error!("Error occurs while encrypting: {:?}", err);
                                            return;
                                        }

                                        if let Err(err) = encryptor.finalize(&mut iv) {
                                            error!("Error occurs while finalizing: {:?}", err);
                                            return;
                                        }

                                        if let Err(err) = captured_socket.send_to(&iv[..], &client_addr) {
                                            error!("Error occurs while sending data: {:?}", err);
                                            return;
                                        }
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
                        let key = method.bytes_to_key(password.as_bytes());
                        let mut decryptor =
                            cipher::with_type(method,
                                              &key[..],
                                              &data[0..method.block_size()],
                                              CryptoMode::Decrypt);
                        let mut decrypted_data = Vec::new();
                        decryptor.update(&data[method.block_size()..], &mut decrypted_data).unwrap();
                        &decryptor.finalize(&mut decrypted_data).unwrap();
                        let mut bufr = BufReader::new(&decrypted_data[..]);

                        let header = socks5::UdpAssociateHeader::read_from(bufr.by_ref()).unwrap();

                        if header.frag != 0 {
                            // Drop it
                            return;
                        }

                        info!("UDP ASSOCIATE {}", header.address);
                        debug!("UDP request {} -> {}", src, header.address);

                        let sockaddr = match &header.address {
                            &Address::SocketAddress(addr) => {
                                client_map.lock()
                                          .unwrap()
                                          .insert(header.address.clone(), src);
                                remote_map.lock()
                                          .unwrap()
                                          .insert(addr.clone(), header.address.clone());
                                addr
                            },
                            &Address::DomainNameAddress(ref dnaddr, port) => {
                                let mut ipaddrs = lookup_host(&dnaddr[..])
                                                    .unwrap_or_else(|err| {
                                                        panic!("Unable to resolve {}: {}", dnaddr, err);
                                                    });

                                let remote_addr = match ipaddrs.next() {
                                    Some(Ok(SocketAddr::V4(addr))) => {
                                        SocketAddr::V4(SocketAddrV4::new(addr.ip().clone(), port))
                                    },
                                    Some(Ok(SocketAddr::V6(addr))) => {
                                        SocketAddr::V6(SocketAddrV6::new(addr.ip().clone(),
                                                                         port,
                                                                         addr.flowinfo(),
                                                                         addr.scope_id()))
                                    },
                                    _ => {
                                        panic!("Failed ot resolve {}", dnaddr);
                                    }
                                };

                                client_map.lock()
                                          .unwrap()
                                          .insert(header.address.clone(), src);
                                remote_map.lock()
                                          .unwrap()
                                          .insert(remote_addr, header.address.clone());
                                remote_addr
                            }
                        };
                        captured_socket.send_to(&decrypted_data[..][header.len()..], &sockaddr).unwrap();
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

impl UdpRelayServer {
    pub fn run(&self) {
        for s in self.config.server.iter() {
            let s = s.clone();
            Builder::new().stack_size(COROUTINE_STACK_SIZE).spawn(move || UdpRelayServer::accept_loop(s));
        }
    }
}
