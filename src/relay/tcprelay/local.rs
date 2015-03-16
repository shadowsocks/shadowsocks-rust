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

use std::net::{TcpListener, TcpStream};
use std::net::{SocketAddr, IpAddr, Shutdown};
use std::net::lookup_host;
use std::io::{self, BufStream, ErrorKind, Read, Write};
use std::thread;
use std::collections::BTreeMap;

use config::Config;

use relay::Relay;
use relay::socks5;
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};
use relay::tcprelay::stream::{EncryptedWriter, DecryptedReader};

use crypto::cipher;
use crypto::cipher::CipherType;
use crypto::CryptoMode;

#[derive(Clone)]
pub struct TcpRelayLocal {
    config: Config,
}

impl TcpRelayLocal {
    pub fn new(c: Config) -> TcpRelayLocal {
        if c.server.is_empty() || c.local.is_none() {
            panic!("You have to provide configuration for server and local");
        }

        TcpRelayLocal {
            config: c,
        }
    }

    fn do_handshake(stream: &mut TcpStream) -> io::Result<()> {
        // Read the handshake header
        let req = try!(socks5::HandshakeRequest::read_from(stream));

        if !req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
            let resp = socks5::HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
            try!(resp.write_to(stream));
            warn!("Currently shadowsocks-rust does not support authentication");
            return Err(io::Error::new(io::ErrorKind::Other,
                                      "Currently shadowsocks-rust does not support authentication",
                                      None));
        }

        // Reply to client
        let resp = socks5::HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
        try!(resp.write_to(stream));
        Ok(())
    }

    fn handle_udp_associate_local(stream: &mut TcpStream, _: &socks5::Address) -> io::Result<()> {
        let sockname = try!(stream.socket_addr());

        let reply = socks5::TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                   socks5::Address::SocketAddress(sockname.ip(), sockname.port()));
        try!(reply.write_to(stream));

        // TODO: record this client's information for udprelay local server to validate
        //       whether the client has already authenticated

        Ok(())
    }

    fn handle_client(mut stream: TcpStream,
                     server_addr: SocketAddr,
                     password: Vec<u8>,
                     encrypt_method: CipherType,
                     enable_udp: bool) {
        TcpRelayLocal::do_handshake(&mut stream)
            .unwrap_or_else(|err| panic!("Error occurs while doing handshake: {:?}", err));

        let sockname = stream.socket_addr()
                             .unwrap_or_else(|err| panic!("Failed to get socket name: {:?}", err));

        let header = match socks5::TcpRequestHeader::read_from(&mut stream) {
            Ok(h) => { h },
            Err(err) => {
                socks5::TcpResponseHeader::new(err.reply,
                                               socks5::Address::SocketAddress(sockname.ip(), sockname.port()));
                error!("Failed to read request header: {}", err);
                return;
            }
        };

        let addr = header.address;

        match header.command {
            socks5::Command::TcpConnect => {
                info!("CONNECT {}", addr);

                let mut remote_stream = match TcpStream::connect(&server_addr) {
                    Err(err) => {
                        match err.kind() {
                            ErrorKind::ConnectionAborted
                                | ErrorKind::ConnectionReset
                                | ErrorKind::ConnectionRefused => {
                                socks5::TcpResponseHeader::new(socks5::Reply::HostUnreachable, addr.clone())
                                    .write_to(&mut stream).unwrap();
                            },
                            _ => {
                                socks5::TcpResponseHeader::new(socks5::Reply::NetworkUnreachable, addr.clone())
                                    .write_to(&mut stream).unwrap();
                            }
                        }
                        error!("Failed to connect remote server: {}", err);
                        return;
                    },
                    Ok(s) => { s },
                };

                let mut buffered_local_stream = BufStream::new(stream.try_clone().unwrap());

                let iv = encrypt_method.gen_init_vec();
                let encryptor = cipher::with_type(encrypt_method,
                                                  &password[..],
                                                  &iv[..],
                                                  CryptoMode::Encrypt);
                remote_stream.write_all(&iv[..]).unwrap();
                let mut encrypt_stream = EncryptedWriter::new(remote_stream.try_clone().unwrap(), encryptor);

                {
                    socks5::TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                   socks5::Address::SocketAddress(sockname.ip(), sockname.port()))
                                .write_to(&mut buffered_local_stream)
                                .unwrap_or_else(|err|
                                    panic!("Error occurs while writing header to local stream: {:?}", err));
                    buffered_local_stream.flush().unwrap();
                    addr.write_to(&mut encrypt_stream).unwrap();
                }

                let addr_cloned = addr.clone();
                let remote_stream_cloned = remote_stream.try_clone().unwrap();
                let local_stream_cloned = stream.try_clone().unwrap();
                thread::spawn(move || {
                    match io::copy(&mut buffered_local_stream, &mut encrypt_stream) {
                        Ok(..) => {},
                        Err(err) => {
                            match err.kind() {
                                ErrorKind::BrokenPipe => {
                                    debug!("{} relay from local to remote stream: {}", addr_cloned, err)
                                },
                                _ => {
                                    error!("{} relay from local to remote stream: {}", addr_cloned, err)
                                }
                            }
                            let _ = remote_stream_cloned.shutdown(Shutdown::Write);
                            let _ = local_stream_cloned.shutdown(Shutdown::Read);
                        }
                    }
                });

                let remote_iv = {
                    let mut iv = Vec::new();
                    remote_stream.try_clone()
                                 .unwrap()
                                 .take(encrypt_method.block_size() as u64)
                                 .read_to_end(&mut iv)
                                 .unwrap();
                    iv
                };
                let decryptor = cipher::with_type(encrypt_method,
                                                  &password[..],
                                                  &remote_iv[..],
                                                  CryptoMode::Decrypt);
                let mut decrypt_stream = DecryptedReader::new(remote_stream, decryptor);
                match io::copy(&mut decrypt_stream, &mut stream) {
                    Err(err) => {
                        match err.kind() {
                            ErrorKind::BrokenPipe => {
                                debug!("{} relay from local to remote stream: {}", addr, err)
                            },
                            _ => {
                                error!("{} relay from local to remote stream: {}", addr, err)
                            }
                        }
                        let _ = decrypt_stream.get_mut().shutdown(Shutdown::Write);
                        let _ = stream.shutdown(Shutdown::Read);
                    },
                    Ok(..) => {},
                }
            },
            socks5::Command::TcpBind => {
                warn!("BIND is not supported");
                socks5::TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                    .write_to(&mut stream)
                    .unwrap_or_else(|err| panic!("Failed to write BIND response: {:?}", err));
            },
            socks5::Command::UdpAssociate => {
                let sockname = stream.peer_addr().unwrap();
                info!("{} requests for UDP ASSOCIATE", sockname);
                if cfg!(feature = "enable-udp") && enable_udp {
                    TcpRelayLocal::handle_udp_associate_local(&mut stream, &addr)
                        .unwrap_or_else(|err| panic!("Failed to write UDP ASSOCIATE response: {:?}", err));
                } else {
                    warn!("UDP ASSOCIATE is disabled");
                    socks5::TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                        .write_to(&mut stream)
                        .unwrap_or_else(|err| panic!("Failed to write UDP ASSOCIATE response: {:?}", err));
                }
            }
        }
    }
}

impl Relay for TcpRelayLocal {
    fn run(&self) {
        let mut server_load_balancer = RoundRobin::new(self.config.server.clone());

        let local_conf = self.config.local.expect("need local configuration");

        let acceptor = match TcpListener::bind(&local_conf) {
            Ok(acpt) => acpt,
            Err(e) => {
                panic!("Error occurs while listening local address: {}", e.to_string());
            }
        };

        info!("Shadowsocks listening on {}", local_conf);

        let mut cached_proxy: BTreeMap<String, IpAddr> = BTreeMap::new();

        for s in acceptor.incoming() {
            let stream = s.unwrap();
            let _ = stream.set_keepalive(self.config.timeout);

            let mut succeed = false;
            for _ in 0..server_load_balancer.total() {
                let ref server_cfg = server_load_balancer.pick_server();
                let addr = {
                    match cached_proxy.get(&server_cfg.addr[..]).map(|x| x.clone()) {
                        Some(addr) => addr,
                        None => {
                            match lookup_host(&server_cfg.addr[..]) {
                                Ok(mut addr_itr) => {
                                    match addr_itr.next() {
                                        None => {
                                            error!("cannot resolve proxy server `{}`", server_cfg.addr);
                                            continue;
                                        },
                                        Some(addr) => {
                                            cached_proxy.insert(server_cfg.addr.clone(), addr.clone().unwrap().ip());
                                            addr.unwrap().ip()
                                        }
                                    }
                                },
                                Err(err) => {
                                    error!("cannot resolve proxy server `{}`: {}", server_cfg.addr, err);
                                    continue;
                                }
                            }
                        }
                    }
                };

                let server_addr = SocketAddr::new(addr.clone(), server_cfg.port);
                debug!("Using proxy `{}:{}` (`{}`)", server_cfg.addr, server_cfg.port, server_addr);
                let encrypt_method = server_cfg.method.clone();
                let pwd = encrypt_method.bytes_to_key(server_cfg.password.as_bytes());
                let enable_udp = self.config.enable_udp;

                thread::spawn(move ||
                    TcpRelayLocal::handle_client(stream,
                                                 server_addr,
                                                 pwd,
                                                 encrypt_method,
                                                 enable_udp));
                succeed = true;
                break;
            }
            if !succeed {
                panic!("All proxy servers are failed!");
            }
        }
    }
}
