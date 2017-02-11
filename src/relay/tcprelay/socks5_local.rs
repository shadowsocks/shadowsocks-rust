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

//! Local server that accepts SOCKS 5 protocol

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::Handle;
use tokio_core::io::Io;
use tokio_core::io::{ReadHalf, WriteHalf};
use tokio_core::io::flush;

use net2::TcpBuilder;

use config::{Config, ServerConfig};

use relay::socks5::{self, HandshakeRequest, HandshakeResponse, Address};
use relay::socks5::{TcpRequestHeader, TcpResponseHeader};
use relay::loadbalancing::server::RoundRobin;
use relay::loadbalancing::server::LoadBalancer;
use relay::{BoxIoFuture, boxed_future};
use relay::tcprelay::crypto_io::EncryptedWrite;

use super::{tunnel, ignore_until_end, try_timeout};

#[derive(Debug, Clone)]
struct UdpConfig {
    enable_udp: bool,
    client_addr: Rc<SocketAddr>,
}

fn handle_socks5_connect(handle: &Handle,
                         (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                         client_addr: SocketAddr,
                         addr: Address,
                         svr_cfg: Rc<ServerConfig>)
                         -> BoxIoFuture<()> {
    let cloned_addr = addr.clone();
    let cloned_svr_cfg = svr_cfg.clone();
    let cloned_handle = handle.clone();
    let cloned_handle2 = handle.clone();
    let timeout = svr_cfg.timeout().clone();
    let fut = super::connect_proxy_server(handle, svr_cfg)
        .and_then(move |svr_s| {
            trace!("Proxy server connected");

            // Tell the client that we are ready
            let header = TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                Address::SocketAddress(client_addr));
            trace!("Send header: {:?}", header);
            let handle = cloned_handle;

            let fut = try_timeout(header.write_to(w), timeout.clone(), &handle);
            let fut = try_timeout(fut.and_then(flush), timeout, &handle);
            fut.map(move |w| (svr_s, w))
        })
        .and_then(move |(svr_s, w)| {
            let handle = cloned_handle2;
            let svr_cfg = cloned_svr_cfg;
            let timeout = svr_cfg.timeout().clone();
            super::proxy_server_handshake(svr_s, svr_cfg, addr, handle.clone()).and_then(move |(svr_r, svr_w)| {
                let cloned_handle = handle.clone();
                let cloned_timeout = timeout.clone();

                let rhalf = svr_r.and_then(move |svr_r| super::copy_timeout(svr_r, w, timeout, handle));
                let whalf = svr_w.and_then(move |svr_w| svr_w.copy_timeout_opt(r, cloned_timeout, cloned_handle));

                tunnel(cloned_addr, whalf, rhalf)
            })
        });

    Box::new(fut)
}

fn handle_socks5_client(handle: &Handle, s: TcpStream, conf: Rc<ServerConfig>, udp_conf: UdpConfig) -> io::Result<()> {
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
                    let fut = resp.write_to(w)
                        .then(|_| {
                            warn!("Currently shadowsocks-rust does not support authentication");
                            Err(io::Error::new(io::ErrorKind::Other,
                                               "Currently shadowsocks-rust does not support authentication"))
                        });
                    boxed_future(fut)
                } else {
                    // Reply to client
                    let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                    trace!("Reply handshake {:?}", resp);
                    let fut = resp.write_to(w).and_then(flush).and_then(|w| Ok((r, w)));
                    boxed_future(fut)
                }
            })
        })
        .and_then(move |(r, w)| {
            // Fetch headers
            TcpRequestHeader::read_from(r).then(move |res| {
                match res {
                    Ok((r, h)) => boxed_future(futures::finished((r, w, h))),
                    Err(err) => {
                        error!("Failed to get TcpRequestHeader: {}", err);
                        let fut = TcpResponseHeader::new(err.reply, Address::SocketAddress(client_addr))
                            .write_to(w)
                            .then(|_| Err(From::from(err)));
                        boxed_future(fut)
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
                    handle_socks5_connect(&cloned_handle, (r, w), cloned_client_addr, addr, conf)
                }
                socks5::Command::TcpBind => {
                    warn!("BIND is not supported");
                    let fut = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                        .write_to(w)
                        .map(|_| ());
                    boxed_future(fut)
                }
                socks5::Command::UdpAssociate => {
                    if udp_conf.enable_udp {
                        info!("UDP ASSOCIATE {}", addr);
                        let fut = TcpResponseHeader::new(socks5::Reply::Succeeded,
                                                         From::from((&*udp_conf.client_addr).clone()))
                            .write_to(w)
                            .and_then(flush)
                            .and_then(|_| {
                                // Hold the connection until it ends by its own
                                ignore_until_end(r).map(|_| ())
                            });

                        boxed_future(fut)
                    } else {
                        warn!("UDP Associate is not enabled");
                        let fut = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                            .write_to(w)
                            .map(|_| ());
                        boxed_future(fut)
                    }
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

/// Starts a TCP local server with Socks5 proxy protocol
pub fn run(config: Rc<Config>, handle: Handle) -> Box<Future<Item = (), Error = io::Error>> {
    let (listener, local_addr) = {
        let local_addr = config.local.as_ref().unwrap();

        let tcp_builder = match local_addr {
                &SocketAddr::V4(..) => TcpBuilder::new_v4(),
                &SocketAddr::V6(..) => TcpBuilder::new_v6(),
            }
            .unwrap_or_else(|err| panic!("Failed to create listener, {}", err));

        super::reuse_port(&tcp_builder)
            .and_then(|builder| builder.reuse_address(true))
            .and_then(|builder| builder.bind(local_addr))
            .unwrap_or_else(|err| panic!("Failed to bind {}, {}", local_addr, err));

        let listener = tcp_builder.listen(1024)
            .and_then(|l| TcpListener::from_listener(l, local_addr, &handle))
            .unwrap_or_else(|err| panic!("Failed to listen, {}", err));

        info!("ShadowSocks TCP Listening on {}", local_addr);
        (listener, local_addr.clone())
    };

    let udp_conf = UdpConfig {
        enable_udp: config.enable_udp,
        client_addr: Rc::new(local_addr),
    };

    let mut servers = RoundRobin::new(&*config);
    let listening = listener.incoming()
        .for_each(move |(socket, addr)| {
            let server_cfg = servers.pick_server();
            trace!("Got connection, addr: {}", addr);
            trace!("Picked proxy server: {:?}", server_cfg);
            handle_socks5_client(&handle, socket, server_cfg, udp_conf.clone())
        });

    Box::new(listening.map_err(|err| {
        error!("Socks5 server run failed: {}", err);
        err
    }))
}