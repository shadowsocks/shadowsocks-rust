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

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::{self, Future, BoxFuture};
use futures::stream::Stream;

use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::Handle;
use tokio_core::io::Io;
use tokio_core::io::{ReadHalf, WriteHalf};
use tokio_core::io::{flush, copy, write_all};

use hyper::method::Method;

use config::{Config, ServerConfig};

use relay::socks5::{self, HandshakeRequest, HandshakeResponse, Address};
use relay::socks5::{TcpRequestHeader, TcpResponseHeader};
use relay::loadbalancing::server::RoundRobin;
use relay::loadbalancing::server::LoadBalancer;

use super::http::{self, HttpRequestFut, HttpResponseFut};

/// TCP relay local server
pub struct TcpRelayLocal {
    config: Arc<Config>,
}

impl TcpRelayLocal {
    pub fn new(config: Arc<Config>) -> TcpRelayLocal {
        TcpRelayLocal { config: config }
    }

    pub fn run(self, handle: Handle) -> Box<Future<Item = (), Error = io::Error>> {
        let tcp_fut = Socks5RelayLocal::new(self.config.clone()).run(handle.clone());
        match &self.config.http_proxy {
            &Some(..) => {
                let http_fut = HttpRelayServer::new(self.config.clone()).run(handle);
                Box::new(tcp_fut.join(http_fut)
                    .map(|_| ()))
            }
            &None => tcp_fut,
        }
    }
}

/// Socks5 local server
pub struct Socks5RelayLocal {
    config: Arc<Config>,
}

impl Socks5RelayLocal {
    pub fn new(config: Arc<Config>) -> Socks5RelayLocal {
        Socks5RelayLocal { config: config }
    }

    fn handle_socks5_connect(handle: &Handle,
                             (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                             client_addr: SocketAddr,
                             addr: Address,
                             svr_cfg: Arc<ServerConfig>)
                             -> BoxFuture<(), io::Error> {
        let cloned_addr = addr.clone();
        super::connect_proxy_server(handle, svr_cfg, addr)
            .and_then(move |(svr_r, svr_w)| {
                let header = TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                    Address::SocketAddress(client_addr));
                trace!("Send header: {:?}", header);

                header.write_to(w)
                    .and_then(|w| flush(w))
                    .and_then(|w| Ok((svr_r, svr_w, w)))
            })
            .and_then(move |(svr_r, svr_w, w)| {
                let c2s = copy(r, svr_w);
                let s2c = copy(svr_r, w);
                c2s.join(s2c)
                    .then(move |_| {
                        trace!("Relay to {} is finished", cloned_addr);
                        Ok(())
                    })
            })
            .boxed()
    }

    fn handle_client(handle: &Handle, s: TcpStream, _: SocketAddr, conf: Arc<ServerConfig>) -> io::Result<()> {
        let cloned_handle = handle.clone();
        let client_addr = try!(s.peer_addr());
        let cloned_client_addr = client_addr.clone();
        let fut = futures::lazy(|| Ok(s.split()))
            .and_then(|(r, w)| {
                // Socks5 handshakes
                HandshakeRequest::read_from(r).and_then(move |(r, req)| {
                    trace!("Socks5 {:?}", req);

                    if !req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
                        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
                        resp.write_to(w)
                            .then(|_| {
                                warn!("Currently shadowsocks-rust does not support authentication");
                                Err(io::Error::new(io::ErrorKind::Other,
                                                   "Currently shadowsocks-rust does not support authentication"))
                            })
                            .boxed()
                    } else {
                        // Reply to client
                        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                        trace!("Reply handshake {:?}", resp);
                        resp.write_to(w).and_then(|w| Ok((r, w))).boxed()
                    }
                })
            })
            .and_then(move |(r, w)| {
                // Fetch headers
                TcpRequestHeader::read_from(r).then(move |res| {
                    match res {
                        Ok((r, h)) => futures::finished((r, w, h)).boxed(),
                        Err(err) => {
                            error!("Failed to get TcpRequestHeader: {}", err);
                            TcpResponseHeader::new(err.reply, Address::SocketAddress(client_addr))
                                .write_to(w)
                                .then(|_| Err(From::from(err)))
                                .boxed()
                        }
                    }
                })
            })
            .and_then(move |(r, w, header)| {
                trace!("Socks5 {:?}", header);

                let addr = header.address;
                match header.command {
                    socks5::Command::TcpConnect => {
                        info!("CONNECT {}", addr);
                        Socks5RelayLocal::handle_socks5_connect(&cloned_handle, (r, w), cloned_client_addr, addr, conf)
                    }
                    socks5::Command::TcpBind => {
                        warn!("BIND is not supported");
                        TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                            .write_to(w)
                            .map(|_| ())
                            .boxed()
                    }
                    socks5::Command::UdpAssociate => {
                        warn!("UDP Associate is not supported");
                        TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                            .write_to(w)
                            .map(|_| ())
                            .boxed()
                    }
                }
            });

        // Runs in Tokio
        handle.spawn(fut.then(|res| {
            match res {
                Ok(..) => Ok(()),
                Err(err) => {
                    if err.kind() != io::ErrorKind::BrokenPipe {
                        error!("Failed to handle client: {}", err);
                    }
                    Err(())
                }
            }
        }));

        Ok(())
    }

    // Runs TCP relay local server
    pub fn run(self, handle: Handle) -> Box<Future<Item = (), Error = io::Error>> {
        let listener = {
            let local_addr = self.config.local.as_ref().unwrap();
            let listener = TcpListener::bind(local_addr, &handle).unwrap();
            info!("ShadowSocks TCP Listening on {}", local_addr);
            listener
        };

        let mut servers = RoundRobin::new(self.config);
        let listening = listener.incoming()
            .for_each(move |(socket, addr)| {
                let server_cfg = servers.pick_server();
                trace!("Got connection, addr: {}", addr);
                trace!("Picked proxy server: {:?}", server_cfg);
                Socks5RelayLocal::handle_client(&handle, socket, addr, server_cfg)
            });

        Box::new(listening.map_err(|err| {
            error!("Socks5 server run failed: {}", err);
            err
        }))
    }
}

/// HTTP local server
pub struct HttpRelayServer {
    config: Arc<Config>,
}

impl HttpRelayServer {
    pub fn new(config: Arc<Config>) -> HttpRelayServer {
        HttpRelayServer { config: config }
    }

    fn handle_connect(handle: Handle,
                      (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                      req: http::HttpRequest,
                      addr: Address,
                      remains: Vec<u8>,
                      svr_cfg: Arc<ServerConfig>)
                      -> BoxFuture<(), io::Error> {
        let cloned_addr = addr.clone();
        let http_version = req.version;
        super::connect_proxy_server(&handle, svr_cfg, addr)
            .and_then(move |(svr_r, svr_w)| {
                let handshake_resp = format!("{} 200 Connection Established\r\n\r\n", http_version);
                trace!("Sending HTTP tunnel handshake response");
                write_all(w, handshake_resp.into_bytes()).and_then(|(w, _)| flush(w)).map(|w| (svr_r, svr_w, w))
            })
            .and_then(move |(svr_r, svr_w, w)| {
                trace!("HTTP tunnel handshake finished, established tunnel");
                write_all(svr_w, remains).map(|(svr_w, _)| (svr_r, svr_w, w))
            })
            .and_then(move |(svr_r, svr_w, w)| {
                let c2s = copy(r, svr_w);
                let s2c = copy(svr_r, w);
                c2s.join(s2c)
                    .then(move |_| {
                        trace!("Relay to {} is finished", cloned_addr);
                        Ok(())
                    })
            })
            .boxed()
    }

    fn handle_http_again((r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                         (svr_r, svr_w): (super::DecryptedHalf, super::EncryptedHalf),
                         client_addr: SocketAddr,
                         (req_remains, rsp_remains): (Vec<u8>, Vec<u8>),
                         svr_cfg: Arc<ServerConfig>)
                         -> BoxFuture<(), io::Error> {
        trace!("Continue proxying HTTP request for {}", client_addr);

        let client_addr_cloned = client_addr.clone();
        HttpRequestFut::with_buf(r, req_remains)
            .and_then(move |(r, req, req_remains)| {
                let svr_addr = svr_cfg.addr.clone();
                let should_keep_alive = http::should_keep_alive(&req);

                trace!("Proxy {} request, keep_alive: {}",
                       req.method,
                       should_keep_alive);

                http::proxy_request((r, svr_w), client_addr, req, req_remains)
                    .and_then(move |(r, svr_w, req_remains)| {
                        HttpResponseFut::with_buf(svr_r, rsp_remains)
                            .and_then(move |(svr_r, rsp, rsp_remains)| {
                                let is_succeed = rsp.status.is_success();
                                http::proxy_response((svr_r, w), svr_addr, rsp, rsp_remains)
                                    .map(move |(svr_r, w, rsp_remains)| (svr_r, w, rsp_remains, is_succeed))
                            })
                            .map(move |(svr_r, w, rsp_remains, is_succeed)| {
                                (r, w, svr_r, svr_w, req_remains, rsp_remains, is_succeed)
                            })
                    })
                    .and_then(move |(r, w, svr_r, svr_w, req_remains, rsp_remains, is_succeed)| {
                        if should_keep_alive && is_succeed {
                            HttpRelayServer::handle_http_again((r, w),
                                                               (svr_r, svr_w),
                                                               client_addr_cloned,
                                                               (req_remains, rsp_remains),
                                                               svr_cfg)
                        } else {
                            trace!("HTTP proxy finished");
                            futures::finished(()).boxed()
                        }
                    })
            })
            .or_else(|err| {
                match err.kind() {
                    io::ErrorKind::UnexpectedEof |
                    io::ErrorKind::BrokenPipe => {
                        // Ignores this kind of errors, normally because of connection aborted
                        Ok(())
                    }
                    _ => Err(err),
                }
            })
            .boxed()
    }

    fn handle_http_proxy(handle: Handle,
                         (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                         client_addr: SocketAddr,
                         req: http::HttpRequest,
                         addr: Address,
                         remains: Vec<u8>,
                         svr_cfg: Arc<ServerConfig>)
                         -> BoxFuture<(), io::Error> {
        let client_addr_cloned = client_addr.clone();
        let should_keep_alive = http::should_keep_alive(&req);

        super::connect_proxy_server(&handle, svr_cfg.clone(), addr)
            .and_then(move |(svr_r, svr_w)| {
                trace!("Proxy {} request, keep_alive: {}",
                       req.method,
                       should_keep_alive);

                let svr_addr = svr_cfg.addr.clone();
                http::proxy_request((r, svr_w), client_addr, req, remains)
                    .and_then(move |(r, svr_w, req_remains)| {
                        HttpResponseFut::new(svr_r)
                            .and_then(move |(svr_r, rsp, rsp_remains)| {
                                trace!("Proxy response, {:?}", rsp);
                                let is_succeed = rsp.status.is_success();
                                http::proxy_response((svr_r, w), svr_addr, rsp, rsp_remains)
                                    .map(move |(svr_r, w, rsp_remains)| (svr_r, w, rsp_remains, is_succeed))
                            })
                            .map(move |(svr_r, w, rsp_remains, is_succeed)| {
                                (r, w, svr_r, svr_w, req_remains, rsp_remains, is_succeed)
                            })
                    })
                    .and_then(move |(r, w, svr_r, svr_w, req_remains, rsp_remains, is_succeed)| {
                        if should_keep_alive && is_succeed {
                            HttpRelayServer::handle_http_again((r, w),
                                                               (svr_r, svr_w),
                                                               client_addr_cloned,
                                                               (req_remains, rsp_remains),
                                                               svr_cfg)
                        } else {
                            trace!("HTTP proxy finished");
                            futures::finished(()).boxed()
                        }
                    })
            })
            .boxed()
    }

    fn handle_client(handle: &Handle, socket: TcpStream, _: SocketAddr, svr_cfg: Arc<ServerConfig>) -> io::Result<()> {
        let cloned_handle = handle.clone();
        let client_addr = try!(socket.peer_addr());
        let fut = futures::lazy(|| Ok(socket.split()))
            .and_then(|(r, w)| {
                HttpRequestFut::new(r).and_then(move |(r, mut req, remains)| {
                    trace!("Got HTTP Request, version: {}, method: {}, uri: {}",
                           req.version,
                           req.method,
                           req.request_uri);

                    match req.get_address() {
                        Ok(addr) => {
                            req.clear_request_uri_host();
                            futures::finished((r, w, req, addr, remains)).boxed()
                        }
                        Err(status_code) => {
                            error!("Invalid Uri: {}", req.request_uri);
                            http::write_response(w, req.version, status_code)
                                .then(|_| {
                                    let err = io::Error::new(io::ErrorKind::Other, "Invalid Uri");
                                    Err(err)
                                })
                                .boxed()
                        }
                    }
                })
            })
            .and_then(move |(r, w, req, addr, remains)| {
                match req.method.clone() {
                    Method::Connect => {
                        info!("CONNECT (Http) {}", addr);
                        HttpRelayServer::handle_connect(cloned_handle, (r, w), req, addr, remains, svr_cfg)
                    }
                    met => {
                        info!("{} (Http) {}", met, addr);
                        HttpRelayServer::handle_http_proxy(cloned_handle,
                                                           (r, w),
                                                           client_addr,
                                                           req,
                                                           addr,
                                                           remains,
                                                           svr_cfg)
                    }
                }
            });

        handle.spawn(fut.then(|res| {
            match res {
                Ok(..) => Ok(()),
                Err(err) => {
                    if err.kind() != io::ErrorKind::BrokenPipe {
                        error!("Failed to handle client: {}", err);
                    }

                    Err(())
                }
            }
        }));

        Ok(())
    }

    pub fn run(self, handle: Handle) -> Box<Future<Item = (), Error = io::Error>> {
        let listener = {
            let local_addr = self.config.http_proxy.as_ref().unwrap();
            let listener = TcpListener::bind(local_addr, &handle).unwrap();
            info!("ShadowSocks HTTP Listening on {}", local_addr);
            listener
        };

        let mut servers = RoundRobin::new(self.config);
        let listening = listener.incoming()
            .for_each(move |(socket, addr)| {
                let server_cfg = servers.pick_server();
                trace!("Got connection, addr: {}", addr);
                trace!("Picked proxy server: {:?}", server_cfg);
                HttpRelayServer::handle_client(&handle, socket, addr, server_cfg)
            });

        Box::new(listening.map_err(|err| {
            error!("HTTP server run failed: {}", err);
            err
        }))
    }
}
