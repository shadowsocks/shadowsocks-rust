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

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::Handle;
use tokio_core::io::Io;
use tokio_core::io::{ReadHalf, WriteHalf};
use tokio_core::io::{flush, write_all, copy};

use hyper::method::Method;

use config::{Config, ServerConfig};

use relay::socks5::{self, HandshakeRequest, HandshakeResponse, Address};
use relay::socks5::{TcpRequestHeader, TcpResponseHeader};
use relay::loadbalancing::server::RoundRobin;
use relay::loadbalancing::server::LoadBalancer;
use relay::BoxIoFuture;
use relay::dns_resolver::DnsResolver;

use super::http::{self, HttpRequestFut};
use super::tunnel;

/// TCP relay local server
pub struct TcpRelayLocal;

impl TcpRelayLocal {
    pub fn run(config: Arc<Config>,
               handle: Handle,
               dns_resolver: DnsResolver)
               -> Box<Future<Item = (), Error = io::Error>> {
        let tcp_fut = Socks5RelayLocal::run(config.clone(), handle.clone(), dns_resolver.clone());
        match &config.http_proxy {
            &Some(..) => {
                let http_fut = HttpRelayServer::run(config, handle, dns_resolver);
                Box::new(tcp_fut.join(http_fut)
                    .map(|_| ()))
            }
            &None => tcp_fut,
        }
    }
}

/// Socks5 local server
pub struct Socks5RelayLocal;

impl Socks5RelayLocal {
    fn handle_socks5_connect(handle: &Handle,
                             (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                             client_addr: SocketAddr,
                             addr: Address,
                             svr_cfg: Arc<ServerConfig>,
                             dns_resolver: DnsResolver)
                             -> Box<Future<Item = (), Error = io::Error>> {
        let cloned_addr = addr.clone();
        let cloned_svr_cfg = svr_cfg.clone();
        let fut = super::connect_proxy_server(handle, svr_cfg, dns_resolver)
            .and_then(move |svr_s| {
                trace!("Proxy server connected");

                // Tell the client that we are ready
                let header = TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                    Address::SocketAddress(client_addr));
                trace!("Send header: {:?}", header);

                header.write_to(w)
                    .and_then(flush)
                    .map(move |w| (svr_s, w))
            })
            .and_then(move |(svr_s, w)| {
                super::proxy_server_handshake(svr_s, cloned_svr_cfg, addr).and_then(move |(svr_r, svr_w)| {
                    let rhalf = svr_r.and_then(move |svr_r| copy(svr_r, w));
                    let whalf = svr_w.and_then(move |svr_w| svr_w.copy_from_encrypted(r));

                    tunnel(cloned_addr, whalf, rhalf)
                })
            });

        Box::new(fut)
    }

    fn handle_client(handle: &Handle,
                     s: TcpStream,
                     _: SocketAddr,
                     conf: Arc<ServerConfig>,
                     dns_resolver: DnsResolver)
                     -> io::Result<()> {
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
                        resp.write_to(w).and_then(flush).and_then(|w| Ok((r, w))).boxed()
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
                        Socks5RelayLocal::handle_socks5_connect(&cloned_handle,
                                                                (r, w),
                                                                cloned_client_addr,
                                                                addr,
                                                                conf,
                                                                dns_resolver)
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
    pub fn run(config: Arc<Config>,
               handle: Handle,
               dns_resolver: DnsResolver)
               -> Box<Future<Item = (), Error = io::Error>> {
        let listener = {
            let local_addr = config.local.as_ref().unwrap();
            let listener = TcpListener::bind(local_addr, &handle).unwrap();
            info!("ShadowSocks TCP Listening on {}", local_addr);
            listener
        };

        let dns_resolver = dns_resolver.clone();

        let mut servers = RoundRobin::new(&*config);
        let listening = listener.incoming()
            .for_each(move |(socket, addr)| {
                let server_cfg = servers.pick_server();
                trace!("Got connection, addr: {}", addr);
                trace!("Picked proxy server: {:?}", server_cfg);
                let dns_resolver = dns_resolver.clone();
                Socks5RelayLocal::handle_client(&handle, socket, addr, server_cfg, dns_resolver)
            });

        Box::new(listening.map_err(|err| {
            error!("Socks5 server run failed: {}", err);
            err
        }))
    }
}

/// HTTP local server
pub struct HttpRelayServer;

impl HttpRelayServer {
    fn handle_connect(handle: Handle,
                      (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                      req: http::HttpRequest,
                      addr: Address,
                      remains: Vec<u8>,
                      svr_cfg: Arc<ServerConfig>,
                      dns_resolver: DnsResolver)
                      -> Box<Future<Item = (), Error = io::Error>> {
        let cloned_addr = addr.clone();
        let http_version = req.version;
        let cloned_svr_cfg = svr_cfg.clone();

        let fut = super::connect_proxy_server(&handle, svr_cfg, dns_resolver)
            .and_then(move |svr_s| {
                trace!("Proxy server connected");

                // Tell the client that we are ready
                let handshake_resp = format!("{} 200 Connection Established\r\n\r\n", http_version);
                trace!("Sending HTTP tunnel handshake response");
                write_all(w, handshake_resp.into_bytes())
                    .and_then(|(w, _)| flush(w))
                    .map(|w| (svr_s, w))
            })
            .and_then(move |(svr_s, w)| {
                super::proxy_server_handshake(svr_s, cloned_svr_cfg, addr).and_then(move |(svr_r, svr_w)| {
                    let rhalf = svr_r.and_then(move |svr_r| copy(svr_r, w));
                    let whalf = svr_w.and_then(move |svr_w| svr_w.write_all_encrypted(remains))
                        .and_then(move |(svr_w, _)| svr_w.copy_from_encrypted(r));

                    tunnel(cloned_addr, whalf, rhalf)
                })
            });

        Box::new(fut)
    }

    fn handle_http_keepalive(r: ReadHalf<TcpStream>,
                             svr_w: super::EncryptedHalf,
                             req_remains: Vec<u8>)
                             -> BoxIoFuture<()> {
        let fut = HttpRequestFut::with_buf(r, req_remains).then(|res| {
            match res {
                Ok((r, req, remains)) => {
                    let should_keep_alive = http::should_keep_alive(&req);
                    trace!("Going to proxy request: {:?}", req);
                    trace!("Should keep alive? {}", should_keep_alive);

                    let fut = http::proxy_request_encrypted((r, svr_w), None, req, remains)
                        .and_then(move |(r, svr_w, req_remains)| {
                            if should_keep_alive {
                                HttpRelayServer::handle_http_keepalive(r, svr_w, req_remains)
                            } else {
                                futures::finished(()).boxed()
                            }
                        });
                    Box::new(fut) as BoxIoFuture<()>
                }
                Err(err) => {
                    let fut = futures::lazy(|| {
                        use std::io::ErrorKind;
                        match err.kind() {
                            // It is Ok for client to close connection
                            ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe => Ok(()),
                            _ => Err(err),
                        }
                    });
                    Box::new(fut) as BoxIoFuture<()>
                }
            }
        });
        Box::new(fut)
    }

    fn handle_http_proxy(handle: Handle,
                         (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                         client_addr: &SocketAddr,
                         req: http::HttpRequest,
                         addr: Address,
                         remains: Vec<u8>,
                         svr_cfg: Arc<ServerConfig>,
                         dns_resolver: DnsResolver)
                         -> Box<Future<Item = (), Error = io::Error>> {
        trace!("Using HTTP Proxy for {} -> {}", client_addr, addr);

        let should_keep_alive = http::should_keep_alive(&req);
        let fut = super::connect_proxy_server(&handle, svr_cfg.clone(), dns_resolver).and_then(move |svr_s| {
            trace!("Proxy server connected");

            let cloned_addr = addr.clone();
            super::proxy_server_handshake(svr_s, svr_cfg, addr).and_then(move |(svr_r, svr_w)| {
                // Just proxy anything to client
                let rhalf = svr_r.and_then(move |svr_r| copy(svr_r, w));
                let whalf = svr_w.and_then(move |svr_w| {
                    // Send the first request to server
                    trace!("Going to proxy request: {:?}", req);
                    trace!("Should keep alive? {}", should_keep_alive);
                    http::proxy_request_encrypted((r, svr_w), None, req, remains)
                        .and_then(move |(r, svr_w, req_remains)| {
                            if should_keep_alive {
                                HttpRelayServer::handle_http_keepalive(r, svr_w, req_remains)
                            } else {
                                futures::finished(()).boxed()
                            }
                        })
                });

                rhalf.join(whalf)
                    .then(move |_| {
                        trace!("Relay to {} is finished", cloned_addr);
                        Ok(())
                    })
            })
        });

        Box::new(fut)
    }

    fn handle_client(handle: &Handle,
                     socket: TcpStream,
                     _: SocketAddr,
                     svr_cfg: Arc<ServerConfig>,
                     dns_resolver: DnsResolver)
                     -> io::Result<()> {
        let cloned_handle = handle.clone();
        let client_addr = try!(socket.peer_addr());
        let fut = futures::lazy(|| Ok(socket.split()))
            .and_then(|(r, w)| {
                // Process the first request to see whether client wants CONNECT tunnel or normal HTTP proxy

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
                        HttpRelayServer::handle_connect(cloned_handle,
                                                        (r, w),
                                                        req,
                                                        addr,
                                                        remains,
                                                        svr_cfg,
                                                        dns_resolver)
                    }
                    met => {
                        info!("{} (Http) {}", met, addr);
                        HttpRelayServer::handle_http_proxy(cloned_handle,
                                                           (r, w),
                                                           &client_addr,
                                                           req,
                                                           addr,
                                                           remains,
                                                           svr_cfg,
                                                           dns_resolver)
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

    pub fn run(config: Arc<Config>,
               handle: Handle,
               dns_resolver: DnsResolver)
               -> Box<Future<Item = (), Error = io::Error>> {
        let listener = {
            let local_addr = config.http_proxy.as_ref().unwrap();
            let listener = TcpListener::bind(local_addr, &handle).unwrap();
            info!("ShadowSocks HTTP Listening on {}", local_addr);
            listener
        };

        let mut servers = RoundRobin::new(&*config);
        let listening = listener.incoming()
            .for_each(move |(socket, addr)| {
                let server_cfg = servers.pick_server();
                trace!("Got connection, addr: {}", addr);
                trace!("Picked proxy server: {:?}", server_cfg);
                let dns_resolver = dns_resolver.clone();
                HttpRelayServer::handle_client(&handle, socket, addr, server_cfg, dns_resolver)
            });

        Box::new(listening.map_err(|err| {
            error!("HTTP server run failed: {}", err);
            err
        }))
    }
}
