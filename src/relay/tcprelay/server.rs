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

//! TcpRelay server that running on the server side

use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::collections::HashSet;

use config::{Config, ServerConfig};

use relay::socks5::Address;
use relay::BoxIoFuture;
use relay::dns_resolver::DnsResolver;

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::reactor::Handle;
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::io::{Io, ReadHalf, WriteHalf};
use tokio_core::io::copy;

use ip::IpAddr;

use super::{tunnel, proxy_handshake, DecryptedHalf, EncryptedHalfFut};

/// Context for doing handshake with client
pub struct TcpRelayClientHandshake {
    handle: Handle,
    dns_resolver: DnsResolver,
    s: TcpStream,
    svr_cfg: Rc<ServerConfig>,
    forbidden_ip: Rc<HashSet<IpAddr>>,
}

impl TcpRelayClientHandshake {
    /// Doing handshake with client
    pub fn handshake(self) -> BoxIoFuture<TcpRelayClientPending> {
        let TcpRelayClientHandshake { handle, forbidden_ip, dns_resolver, s, svr_cfg } = self;

        let fut = proxy_handshake(s, svr_cfg).and_then(|(r_fut, w_fut)| {
            r_fut.and_then(|r| Address::read_from(r).map_err(From::from))
                .map(move |(r, addr)| {
                    TcpRelayClientPending {
                        handle: handle,
                        r: r,
                        addr: addr,
                        w: w_fut,
                        forbidden_ip: forbidden_ip,
                        dns_resolver: dns_resolver,
                    }
                })
        });
        Box::new(fut)
    }
}

/// Context for connecting remote
pub struct TcpRelayClientPending {
    handle: Handle,
    r: DecryptedHalf,
    addr: Address,
    w: EncryptedHalfFut,
    forbidden_ip: Rc<HashSet<IpAddr>>,
    dns_resolver: DnsResolver,
}

impl TcpRelayClientPending {
    /// Resolve Address to SocketAddr
    fn resolve_address(addr: Address, dns_resolver: DnsResolver) -> BoxIoFuture<SocketAddr> {
        match addr {
            Address::SocketAddress(addr) => Box::new(futures::finished(addr)),
            Address::DomainNameAddress(dname, port) => {
                let fut = dns_resolver.resolve(&dname[..])
                    .and_then(move |ipaddr| {
                        Ok(match ipaddr {
                            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                        })
                    });
                Box::new(fut)
            }
        }
    }

    /// Resolve remote address to SocketAddr
    /// Report failure if the SocketAddr is forbidden by `forbidden_ip`
    fn resolve_remote(dns_resolver: DnsResolver,
                      addr: Address,
                      forbidden_ip: Rc<HashSet<IpAddr>>)
                      -> BoxIoFuture<SocketAddr> {
        let fut = TcpRelayClientPending::resolve_address(addr, dns_resolver).and_then(move |addr| {
            trace!("Resolved address as {}", addr);
            let ipaddr = match addr.clone() {
                SocketAddr::V4(v4) => IpAddr::V4(v4.ip().clone()),
                SocketAddr::V6(v6) => IpAddr::V6(v6.ip().clone()),
            };

            if forbidden_ip.contains(&ipaddr) {
                info!("{} has been forbidden", ipaddr);
                let err = io::Error::new(io::ErrorKind::Other, "Forbidden IP");
                Err(err)
            } else {
                Ok(addr)
            }
        });
        Box::new(fut)
    }

    /// Connect to the remote server
    fn connect_remote(dns_resolver: DnsResolver,
                      handle: Handle,
                      addr: Address,
                      forbidden_ip: Rc<HashSet<IpAddr>>)
                      -> BoxIoFuture<TcpStream> {
        trace!("Connecting to remote {}", addr);
        Box::new(TcpRelayClientPending::resolve_remote(dns_resolver, addr, forbidden_ip)
            .and_then(move |addr| TcpStream::connect(&addr, &handle)))
    }

    /// Connect to the remote server
    pub fn connect(self) -> BoxIoFuture<TcpRelayClientConnected> {
        let addr = self.addr.clone();
        let client_pair = (self.r, self.w);
        let fut = TcpRelayClientPending::connect_remote(self.dns_resolver, self.handle, self.addr, self.forbidden_ip)
            .map(|stream| {
                TcpRelayClientConnected {
                    server: stream.split(),
                    client: client_pair,
                    addr: addr,
                }
            });
        Box::new(fut)
    }
}

/// Context for extablishing tunnel
pub struct TcpRelayClientConnected {
    server: (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
    client: (DecryptedHalf, EncryptedHalfFut),
    addr: Address,
}

impl TcpRelayClientConnected {
    /// Establish tunnel
    pub fn tunnel(self) -> BoxIoFuture<()> {
        let (svr_r, svr_w) = self.server;
        let (r, w_fut) = self.client;
        tunnel(self.addr,
               copy(r, svr_w),
               w_fut.and_then(|w| w.copy_from_encrypted(svr_r)))
    }
}

/// Runs the server
pub fn run(config: Rc<Config>, handle: Handle, dns_resolver: DnsResolver) -> Box<Future<Item = (), Error = io::Error>> {
    let mut fut: Option<Box<Future<Item = (), Error = io::Error>>> = None;

    let ref forbidden_ip = config.forbidden_ip;
    let forbidden_ip = Rc::new(forbidden_ip.clone());

    for svr_cfg in &config.server {
        let listener = {
            let addr = svr_cfg.addr();
            let addr = addr.listen_addr();
            let listener = TcpListener::bind(addr, &handle).unwrap();
            trace!("ShadowSocks TCP Listening on {}", addr);
            listener
        };

        let svr_cfg = Rc::new(svr_cfg.clone());
        let handle = handle.clone();
        let dns_resolver = dns_resolver.clone();
        let forbidden_ip = forbidden_ip.clone();
        let listening = listener.incoming()
            .for_each(move |(socket, addr)| {
                let server_cfg = svr_cfg.clone();
                let forbidden_ip = forbidden_ip.clone();
                let dns_resolver = dns_resolver.clone();

                trace!("Got connection, addr: {}", addr);
                trace!("Picked proxy server: {:?}", server_cfg);

                let client = TcpRelayClientHandshake {
                    handle: handle.clone(),
                    dns_resolver: dns_resolver,
                    s: socket,
                    svr_cfg: server_cfg,
                    forbidden_ip: forbidden_ip,
                };

                let fut = client.handshake()
                    .and_then(|c| c.connect())
                    .and_then(|c| c.tunnel())
                    .map_err(move |err| {
                        error!("Failed to handle client ({}): {}", addr, err);
                    });

                handle.spawn(fut);
                Ok(())
            })
            .map_err(|err| {
                error!("Server run failed: {}", err);
                err
            });

        fut = Some(match fut.take() {
            Some(fut) => Box::new(fut.join(listening).map(|_| ())) as Box<Future<Item = (), Error = io::Error>>,
            None => Box::new(listening) as Box<Future<Item = (), Error = io::Error>>,
        })
    }

    fut.expect("Must have at least one server")
}
