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

use std::sync::{Arc, Mutex};
use std::net::{SocketAddr, lookup_host};
use std::collections::HashMap;
use std::io::{BufReader, self};

use coio::Builder;
use coio::net::UdpSocket;

use lru_cache::LruCache;

use crypto::{cipher, CryptoMode};
use crypto::cipher::Cipher;
use config::{Config, ServerConfig};
use relay::{socks5, COROUTINE_STACK_SIZE};
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};
use relay::udprelay::UDP_RELAY_LOCAL_LRU_CACHE_CAPACITY;

#[derive(Clone)]
pub struct UdpRelayLocal {
    config: Config,
}

impl UdpRelayLocal {
    pub fn new(config: Config) -> UdpRelayLocal {
        UdpRelayLocal {
            config: config,
        }
    }
}

impl UdpRelayLocal {
    pub fn run(&self) {
        let addr = match self.config.local {
            Some(addr) => addr,
            None => {
                error!("Local configuration should not be None");
                return;
            }
        };

        let mut server_load_balancer = RoundRobin::new(self.config.server.clone());

        let (server_set, server_addr) = {
            let mut server_set = HashMap::new();
            let mut server_addr = HashMap::new();
            for s in self.config.server.iter() {
                let mut addrs = match lookup_host(&s.addr[..]) {
                    Ok(addr) => addr,
                    Err(..) => continue,
                };

                match addrs.next() {
                    Some(Ok(addr)) => {
                        server_set.insert(addr, s.clone());
                        server_addr.insert(s.addr.clone(), addr);
                    },
                    _ => {}
                }
            }
            (server_set, server_addr)
        };

        let client_map_arc = Arc::new(Mutex::new(
                    LruCache::<socks5::Address, SocketAddr>::new(UDP_RELAY_LOCAL_LRU_CACHE_CAPACITY)));

        let socket = match UdpSocket::bind(&addr) {
            Ok(sk) => sk,
            Err(err) => {
                error!("Failed to bind udp socket: {:?}", err);
                return;
            }
        };

        let mut buf = [0u8; 0xffff];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, source_addr)) => {
                    if len < 4 {
                        error!("UDP request is too short");
                        continue;
                    }

                    let request_message = buf[..len].to_vec();
                    let move_socket = socket.try_clone().unwrap();
                    let client_map = client_map_arc.clone();

                    match server_set.get(&source_addr) {
                        Some(sref) => {
                            let s = sref.clone();
                            Builder::new().stack_size(COROUTINE_STACK_SIZE).spawn(move ||
                                handle_response(move_socket,
                                               &request_message[..],
                                               source_addr,
                                               &s,
                                               client_map));
                        }
                        None => {
                            let s = server_load_balancer.pick_server().clone();
                            debug!("UDP associate picked a server: {:?}", s);

                            match server_addr.get(&s.addr) {
                                Some(saddr) => {
                                    let saddr = saddr.clone();
                                    Builder::new().stack_size(COROUTINE_STACK_SIZE).spawn(move ||
                                        handle_request(move_socket,
                                                      &request_message[..],
                                                      source_addr,
                                                      saddr,
                                                      &s,
                                                      client_map));
                                },
                                None => {}
                            }
                        }
                    }
                },
                Err(err) => {
                    error!("Failed in UDP recv_from: {}", err);
                    break
                }
            }
        }
    }
}

fn handle_request(socket: UdpSocket,
                  request_message: &[u8],
                  from_addr: SocketAddr,
                  server_addr: SocketAddr,
                  config: &ServerConfig,
                  client_map: Arc<Mutex<LruCache<socks5::Address, SocketAddr>>>) {
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


    let mut bufr = BufReader::new(request_message);
    let request = match socks5::UdpAssociateHeader::read_from(&mut bufr) {
        Ok(r) => r,
        Err(err) => {
            error!("Error occurs while reading UdpAssociateHeader: {:?}", err);
            return;
        }
    };

    let addr = request.address.clone();

    info!("UDP ASSOCIATE {}", addr);
    debug!("UDP associate {} <-> {}", addr, from_addr);

    client_map.lock().unwrap().insert(addr, from_addr);

    let key = config.method.bytes_to_key(config.password.as_bytes());
    let mut iv = config.method.gen_init_vec();
    let mut encryptor = cipher::with_type(config.method,
                                          &key[..],
                                          &iv[..],
                                          CryptoMode::Encrypt);

    let mut wbuf = Vec::new();
    if let Err(err) = request.write_to(&mut wbuf) {
        error!("Error occurs while writing request: {:?}", err);
        return;
    }

    if let Err(err) = io::copy(&mut bufr, &mut wbuf) {
        error!("Error occurs while copying from bufr to wbuf: {:?}", err);
        return;
    }

    if let Err(err) = encryptor.update(&wbuf[..], &mut iv) {
        error!("Error occurs while encrypting: {:?}", err);
        return;
    }

    if let Err(err) = encryptor.finalize(&mut iv) {
        error!("Error occurs while finalizing: {:?}", err);
        return;
    }

    if let Err(err) = socket.send_to(&iv[..], &server_addr) {
        error!("Error occurs while sending to remote: {:?}", err);
    }
}

fn handle_response(socket: UdpSocket,
                   response_message: &[u8],
                   from_addr: SocketAddr,
                   config: &ServerConfig,
                   client_map: Arc<Mutex<LruCache<socks5::Address, SocketAddr>>>) {
    let key = config.method.bytes_to_key(config.password.as_bytes());

    let mut decryptor = cipher::with_type(config.method,
                                          &key[..],
                                          &response_message[0..config.method.block_size()],
                                          CryptoMode::Decrypt);
    let mut decrypted_data = Vec::new();
    if let Err(err) = decryptor.update(&response_message[config.method.block_size()..], &mut decrypted_data) {
        error!("Error occurs while decrypting data: {:?}", err);
        return;
    }

    if let Err(err) = decryptor.finalize(&mut decrypted_data) {
        error!("Error occurs while finalizing decrypt: {:?}", err);
        return;
    }

    let mut bufr = BufReader::new(&decrypted_data[..]);

    let addr = match socks5::Address::read_from(&mut bufr) {
        Ok(addr) => addr,
        Err(err) => {
            error!("Error occurs while reading address: {:?}", err);
            return;
        }
    };

    let client_addr = {
        let mut cmap = client_map.lock().unwrap();
        match cmap.get(&addr) {
            Some(a) => a.clone(),
            None => return
        }
    };

    debug!("UDP response {} -> {}", from_addr, client_addr);

    let mut bufw = Vec::new();
    if let Err(err) = socks5::UdpAssociateHeader::new(0, addr).write_to(&mut bufw) {
        error!("Error occurs while writing UdpAssociateHeader: {:?}", err);
        return;
    }

    if let Err(err) = io::copy(&mut bufr, &mut bufw) {
        error!("Error occurs while copying from bufr to bufw: {:?}", err);
        return;
    }

    if let Err(err) = socket.send_to(&bufw[..], &client_addr) {
        error!("Error occurs while sending to local: {:?}", err);
    }
}
