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

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::net::lookup_host;
use std::io::{self, BufWriter, BufReader, Read, Write};
use std::collections::BTreeMap;
use std::sync::Arc;

use coio::Scheduler;
use coio::net::{TcpListener, TcpStream, Shutdown};

use hyper::net::NetworkStream;
use hyper::server::request::Request;
use hyper::method::Method;
use hyper::status::StatusCode;

use config::{Config, ClientConfig};

use relay::socks5::{self, Address};
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};

use crypto::cipher::CipherType;

#[derive(Clone)]
pub struct TcpRelayLocal {
    config: Arc<Config>,
}

impl TcpRelayLocal {
    pub fn new(c: Config) -> TcpRelayLocal {
        if c.server.is_empty() || c.local.is_none() {
            panic!("You have to provide configuration for server and local");
        }

        TcpRelayLocal { config: Arc::new(c) }
    }

    fn do_handshake<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> io::Result<()> {
        // Read the handshake header
        let req = try!(socks5::HandshakeRequest::read_from(reader));
        trace!("Got handshake {:?}", req);

        if !req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
            let resp = socks5::HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
            try!(resp.write_to(writer));
            warn!("Currently shadowsocks-rust does not support authentication");
            return Err(io::Error::new(io::ErrorKind::Other,
                                      "Currently shadowsocks-rust does not support \
                                       authentication"));
        }

        // Reply to client
        let resp = socks5::HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
        trace!("Reply handshake {:?}", resp);
        resp.write_to(writer)
    }

    fn handle_udp_associate_local<W: Write>(stream: &mut W,
                                            _addr: SocketAddr,
                                            _dest_addr: &socks5::Address,
                                            local_conf: ClientConfig)
                                            -> io::Result<()> {
        let reply = socks5::TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                   socks5::Address::SocketAddress(local_conf));
        trace!("Replying Header for UDP ASSOCIATE, {:?}", reply);
        try!(reply.write_to(stream));

        // TODO: record this client's information for udprelay local server to validate
        //       whether the client has already authenticated

        Ok(())
    }

    fn handle_tcp_client(stream: TcpStream,
                         server_addr: SocketAddr,
                         password: Vec<u8>,
                         encrypt_method: CipherType,
                         enable_udp: bool,
                         conf: Arc<Config>) {
        let sockname = match stream.peer_addr() {
            Ok(sockname) => sockname,
            Err(err) => {
                error!("Failed to get peer addr: {}", err);
                return;
            }
        };

        let stream_writer = match stream.try_clone() {
            Ok(s) => s,
            Err(err) => {
                error!("Failed to clone local stream: {}", err);
                return;
            }
        };
        let mut local_reader = BufReader::new(stream);
        let mut local_writer = BufWriter::new(stream_writer);

        if let Err(err) = TcpRelayLocal::do_handshake(&mut local_reader, &mut local_writer) {
            error!("Error occurs while doing handshake: {}", err);
            return;
        }

        if let Err(err) = local_writer.flush() {
            error!("Error occurs while flushing local writer: {}", err);
            return;
        }

        let header = match socks5::TcpRequestHeader::read_from(&mut local_reader) {
            Ok(h) => h,
            Err(err) => {
                let header = socks5::TcpResponseHeader::new(err.reply, socks5::Address::SocketAddress(sockname));
                error!("Failed to read request header: {}", err);
                if let Err(err) = header.write_to(&mut local_writer) {
                    error!("Failed to write response header to local stream: {}", err);
                }
                return;
            }
        };

        trace!("Got header {:?}", header);

        let addr = header.address;

        match header.command {
            socks5::Command::TcpConnect => {
                info!("CONNECT {}", addr);

                let (mut decrypt_stream, mut encrypt_stream) =
                    match super::connect_proxy_server(&server_addr, encrypt_method, &password[..], &addr) {
                        Ok(x) => x,
                        Err(err) => {
                            error!("Failed to connect to proxy server: {:?}", err);
                            return;
                        }
                    };

                // Send header to client
                {
                    let header = socks5::TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                                socks5::Address::SocketAddress(sockname));
                    trace!("Send header to client {:?}", header);
                    if let Err(err) = header.write_to(&mut local_writer)
                        .and_then(|_| local_writer.flush()) {
                        error!("Error occurs while writing header to local stream: {}", err);
                        return;
                    }
                }

                let addr_cloned = addr.clone();

                Scheduler::spawn(move || {
                    loop {
                        match ::relay::copy_once(&mut local_reader, &mut encrypt_stream) {
                            Ok(0) => {
                                trace!("{} local -> remote: EOF", addr_cloned);
                                break;
                            }
                            Ok(n) => {
                                trace!("{} local -> remote: relayed {} bytes", addr_cloned, n);
                            }
                            Err(err) => {
                                error!("SYSTEM Connect {} local -> remote: {}", addr_cloned, err);
                                break;
                            }
                        }
                    }

                    debug!("SYSTEM Connect {} local -> remote is closing", addr_cloned);

                    let _ = encrypt_stream.get_ref().shutdown(Shutdown::Both);
                    let _ = local_reader.get_ref().shutdown(Shutdown::Both);
                });

                Scheduler::spawn(move || {
                    let mut local_writer = match local_writer.into_inner() {
                        Ok(writer) => writer,
                        Err(err) => {
                            error!("Error occurs while taking out local writer: {}", err);
                            return;
                        }
                    };

                    loop {
                        match ::relay::copy_once(&mut decrypt_stream, &mut local_writer) {
                            Ok(0) => {
                                trace!("{} local <- remote: EOF", addr);
                                break;
                            }
                            Ok(n) => {
                                trace!("{} local <- remote: relayed {} bytes", addr, n);
                            }
                            Err(err) => {
                                error!("SYSTEM Connect {} local <- remote: {}", addr, err);
                                break;
                            }
                        }
                    }

                    let _ = local_writer.flush();

                    debug!("SYSTEM Connect {} local <- remote is closing", addr);

                    let _ = decrypt_stream.get_mut().shutdown(Shutdown::Both);
                    let _ = local_writer.shutdown(Shutdown::Both);
                });
            }
            socks5::Command::TcpBind => {
                warn!("BIND is not supported");
                socks5::TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                    .write_to(&mut local_writer)
                    .unwrap_or_else(|err| error!("Failed to write BIND response: {}", err));
            }
            socks5::Command::UdpAssociate => {
                info!("{} requests for UDP ASSOCIATE", sockname);
                if cfg!(feature = "enable-udp") && enable_udp {
                    TcpRelayLocal::handle_udp_associate_local(&mut local_writer, sockname, &addr, conf.local.unwrap())
                        .unwrap_or_else(|err| error!("Failed to write UDP ASSOCIATE response: {}", err));
                } else {
                    warn!("UDP ASSOCIATE is disabled");
                    socks5::TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                        .write_to(&mut local_writer)
                        .unwrap_or_else(|err| error!("Failed to write UDP ASSOCIATE response: {}", err));
                }
            }
        }
    }

    fn handle_http_connect(stream: TcpStream,
                           stream_writer: TcpStream,
                           addr: Address,
                           server_addr: SocketAddr,
                           password: Vec<u8>,
                           encrypt_method: CipherType)
                           -> io::Result<()> {
        info!("CONNECT (Http) {}", addr);

        let mut local_reader = BufReader::new(stream);
        let mut local_writer = stream_writer;

        if let Err(err) = local_writer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n") {
            error!("Failed to send handshake: {:?}", err);
            return Err(err);
        }

        let (mut decrypt_stream, mut encrypt_stream) =
            match super::connect_proxy_server(&server_addr, encrypt_method, &password[..], &addr) {
                Ok(x) => x,
                Err(err) => {
                    error!("Failed to connect to proxy server: {:?}", err);
                    return Err(err);
                }
            };

        let addr_cloned = addr.clone();

        Scheduler::spawn(move || {
            loop {
                match ::relay::copy_once(&mut local_reader, &mut encrypt_stream) {
                    Ok(0) => {
                        trace!("{} local -> remote: EOF", addr_cloned);
                        break;
                    }
                    Ok(n) => {
                        trace!("{} local -> remote: relayed {} bytes", addr_cloned, n);
                    }
                    Err(err) => {
                        error!("SYSTEM Connect {} local -> remote: {}", addr_cloned, err);
                        break;
                    }
                }
            }

            debug!("SYSTEM Connect {} local -> remote is closing", addr_cloned);

            let _ = encrypt_stream.get_ref().shutdown(Shutdown::Both);
            let _ = local_reader.get_ref().shutdown(Shutdown::Both);
        });

        Scheduler::spawn(move || {
            loop {
                match ::relay::copy_once(&mut decrypt_stream, &mut local_writer) {
                    Ok(0) => {
                        trace!("{} local <- remote: EOF", addr);
                        break;
                    }
                    Ok(n) => {
                        trace!("{} local <- remote: relayed {} bytes", addr, n);
                    }
                    Err(err) => {
                        error!("SYSTEM Connect {} local <- remote: {}", addr, err);
                        break;
                    }
                }
            }

            let _ = local_writer.flush();

            debug!("SYSTEM Connect {} local <- remote is closing", addr);

            let _ = decrypt_stream.get_mut().shutdown(Shutdown::Both);
            let _ = local_writer.shutdown(Shutdown::Both);
        });

        Ok(())
    }

    fn handle_http_client(stream: TcpStream, server_addr: SocketAddr, password: Vec<u8>, encrypt_method: CipherType) {
        use hyper::buffer::BufReader;
        use super::http::{HttpStream, get_address, write_response};

        let sockname = match stream.peer_addr() {
            Ok(sockname) => sockname,
            Err(err) => {
                error!("Failed to get peer addr: {}", err);
                return;
            }
        };

        let mut stream_writer = match stream.try_clone() {
            Ok(s) => s,
            Err(err) => {
                error!("Failed to clone stream: {:?}", err);
                return;
            }
        };

        let mut http_stream = HttpStream(stream);

        let opt_stream = {
            let opt_addr = {
                let mut reader = BufReader::new(&mut http_stream as &mut NetworkStream);
                let request = match Request::new(&mut reader, sockname) {
                    Ok(r) => r,
                    Err(err) => {
                        error!("Failed to create Request: {:?}", err);
                        let _ = write_response(&mut stream_writer, StatusCode::BadRequest);
                        return;
                    }
                };

                let addr = match get_address(&request.uri) {
                    Ok(addr) => addr,
                    Err(status) => {
                        let _ = write_response(&mut stream_writer, status);
                        return;
                    }
                };

                match request.method {
                    Method::Connect => Some(addr),
                    method => {
                        info!("{} (Http) {} (Not supported)", method, addr);
                        let _ = write_response(&mut stream_writer, StatusCode::MethodNotAllowed);

                        None
                    }
                }
            };

            opt_addr.map(move |addr| {
                let HttpStream(stream) = http_stream;  // Deconstruct
                (stream, addr)
            })
        };

        if let Some((stream, addr)) = opt_stream {
            // CONNECT
            let _ = TcpRelayLocal::handle_http_connect(stream,
                                                       stream_writer,
                                                       addr,
                                                       server_addr,
                                                       password,
                                                       encrypt_method);
        }
    }
}



impl TcpRelayLocal {
    fn run_server<F>(&self, local_conf: SocketAddr, handler: F)
        where F: Fn(TcpStream, SocketAddr, Vec<u8>, CipherType, Arc<Config>)
    {
        let mut server_load_balancer = RoundRobin::new(self.config.server.clone());

        let acceptor = match TcpListener::bind(&local_conf) {
            Ok(acpt) => acpt,
            Err(e) => {
                panic!("Error occurs while listening local address: {}",
                       e.to_string());
            }
        };

        info!("Shadowsocks listening on {}", local_conf);

        let mut cached_proxy: BTreeMap<String, SocketAddr> = BTreeMap::new();

        for s in acceptor.incoming() {
            let stream = match s {
                Ok((s, addr)) => {
                    debug!("Got connection from client {:?}", addr);
                    s
                }
                Err(err) => {
                    panic!("Error occurs while accepting: {:?}", err);
                }
            };

            if let Err(err) = stream.set_read_timeout(self.config.timeout) {
                error!("Failed to set read timeout: {:?}", err);
                continue;
            }

            if let Err(err) = stream.set_nodelay(true) {
                error!("Failed to set no delay: {:?}", err);
                continue;
            }

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
                                        }
                                        Some(addr) => {
                                            let addr = addr.clone();
                                            cached_proxy.insert(server_cfg.addr.clone(), addr.clone());
                                            addr
                                        }
                                    }
                                }
                                Err(err) => {
                                    error!("cannot resolve proxy server `{}`: {}", server_cfg.addr, err);
                                    continue;
                                }
                            }
                        }
                    }
                };

                let server_addr = match addr {
                    SocketAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr.ip().clone(), server_cfg.port)),
                    SocketAddr::V6(addr) => {
                        SocketAddr::V6(SocketAddrV6::new(addr.ip().clone(),
                                                         server_cfg.port,
                                                         addr.flowinfo(),
                                                         addr.scope_id()))
                    }
                };

                if self.config.forbidden_ip.contains(&::relay::take_ip_addr(&server_addr)) {
                    info!("{} is in `forbidden_ip` list, skipping", server_addr);
                    continue;
                }

                debug!("Using proxy `{}:{}` (`{}`)",
                       server_cfg.addr,
                       server_cfg.port,
                       server_addr);
                let encrypt_method = server_cfg.method.clone();
                let pwd = encrypt_method.bytes_to_key(server_cfg.password.as_bytes());

                let conf = self.config.clone();
                handler(stream, server_addr, pwd, encrypt_method, conf);

                succeed = true;
                break;
            }

            if !succeed {
                panic!("All proxy servers are failed!");
            }
        }
    }

    pub fn run_tcp(&self) {
        self.run_server(self.config.local.expect("Require local config"),
                        |stream, server_addr, pwd, encrypt_method, conf| {
                            let enable_udp = conf.enable_udp;
                            Scheduler::spawn(move || {
                TcpRelayLocal::handle_tcp_client(stream, server_addr, pwd, encrypt_method, enable_udp, conf);
            });
                        });
    }

    pub fn run_http(&self) {
        self.run_server(self.config.http_proxy.expect("Require local config"),
                        |stream, server_addr, pwd, encrypt_method, _| {
                            Scheduler::spawn(move || {
                                TcpRelayLocal::handle_http_client(stream, server_addr, pwd, encrypt_method);
                            });
                        });
    }
}
