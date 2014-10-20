#[phase(plugin, link)]
extern crate log;

use std::sync::Arc;
use std::io::{Listener, TcpListener, Acceptor, TcpStream};
use std::io::net::ip::{Port, IpAddr};
use std::io::{EndOfFile, TimedOut};

use config::Config;
use relay::Relay;
use relay::{parse_request_header, Sock5SocketAddr, Sock5DomainNameAddr};

use crypto::cipher;
use crypto::cipher::Cipher;
use crypto::cipher::CipherVariant;

use std::io::net::addrinfo::get_host_addresses;

pub struct TcpRelayServer {
    config: Config,
}

impl TcpRelayServer {
    pub fn new(c: Config) -> TcpRelayServer {
        TcpRelayServer {
            config: c,
        }
    }

    fn connect_remote(addrs: Vec<IpAddr>, port: Port) -> Option<TcpStream> {
        for addr in addrs.iter() {
            match TcpStream::connect(addr.to_string().as_slice(), port) {
                Ok(s) => {
                    return Some(s)
                },
                Err(..) => {}
            }
        }
        None
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
                                EndOfFile | TimedOut => {},
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
                        EndOfFile | TimedOut => {},
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
                    remote_stream.write(decrypted_msg.as_slice())
                            .ok().expect("Error occurs while writing to remote stream");
                },
                Err(err) => {
                    match err.kind {
                        EndOfFile | TimedOut => {},
                        _ => {
                            error!("Error occurs while reading from client stream: {}", err);
                        }
                    }
                    break
                }
            }
        }
    }
}

impl Relay for TcpRelayServer {
    fn run(&self) {
        let server_addr = self.config.server.as_slice();
        let server_port = self.config.server_port;

        let password = Arc::new(self.config.password.clone());
        let encrypt_method = Arc::new(self.config.method.clone());

        let timeout = match self.config.timeout {
            Some(timeout) => Some(timeout * 1000),
            None => None
        };

        let mut acceptor = match TcpListener::bind(server_addr, server_port).listen() {
            Ok(acpt) => acpt,
            Err(e) => {
                fail!("Error occurs while listening server address: {}", e.to_string());
            }
        };

        info!("Shadowsocks listening on {}:{}", server_addr, server_port);

        loop {
            match acceptor.accept() {
                Ok(mut stream) => {
                    stream.set_timeout(timeout);

                    let password = password.clone();
                    let encrypt_method = encrypt_method.clone();

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

                        let (_, addr) = parse_request_header(&mut stream, header.as_slice());
                        info!("Connecting to {}", addr);
                        let mut remote_stream = match addr {
                            Sock5SocketAddr(sockaddr) => {
                                TcpStream::connect(sockaddr.ip.to_string().as_slice(), sockaddr.port)
                                        .ok().expect("Unable to connect to remote")
                            },
                            Sock5DomainNameAddr(domainaddr) => {
                                let addrs = match get_host_addresses(domainaddr.domain_name.as_slice()) {
                                    Ok(ipaddrs) => ipaddrs,
                                    Err(e) => {
                                        fail!("Error occurs while get_host_addresses: {}", e);
                                    }
                                };

                                if addrs.len() == 0 {
                                    fail!("Cannot resolve host {}, empty host list", domainaddr.domain_name);
                                }

                                TcpRelayServer::connect_remote(addrs, domainaddr.port)
                                        .expect(format!("Unable to resolve {}", domainaddr.domain_name).as_slice())
                            }
                        };

                        let mut remote_local_stream = stream.clone();
                        let mut remote_remote_stream = remote_stream.clone();
                        let mut remote_cipher = cipher.clone();
                        spawn(proc() {
                            TcpRelayServer::handle_connect_remote(&mut remote_local_stream,
                                                                  &mut remote_remote_stream,
                                                                  &mut remote_cipher);
                        });

                        TcpRelayServer::handle_connect_local(&mut stream,
                                                             &mut remote_stream,
                                                             &mut cipher);
                    });
                },
                Err(e) => {
                    fail!("Error occurs while accepting: {}", e.to_string());
                }
            }
        }
    }
}
