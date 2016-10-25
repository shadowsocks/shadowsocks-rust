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
use std::sync::Arc;
use std::collections::HashSet;

use config::{Config, ServerConfig};

use relay::socks5::Address;
use relay::BoxIoFuture;
use relay::dns_resolver::DnsResolver;

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::reactor::Handle;
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::io::Io;
use tokio_core::io::copy;

use ip::IpAddr;

use super::{tunnel, proxy_handshake, DecryptedHalf, EncryptedHalfFut};

/// TCP Relay backend
pub struct TcpRelayServer;

impl TcpRelayServer {
    fn handshake(remote_stream: TcpStream,
                 svr_cfg: Arc<ServerConfig>)
                 -> BoxIoFuture<(DecryptedHalf, Address, EncryptedHalfFut)> {
        let fut = proxy_handshake(remote_stream, svr_cfg).and_then(|(r_fut, w_fut)| {
            r_fut.and_then(|r| Address::read_from(r).map_err(From::from))
                .map(move |(r, addr)| (r, addr, w_fut))
        });
        Box::new(fut)
    }

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

    fn resolve_remote(dns_resolver: DnsResolver,
                      addr: Address,
                      forbidden_ip: Arc<HashSet<IpAddr>>)
                      -> BoxIoFuture<SocketAddr> {
        let fut = TcpRelayServer::resolve_address(addr, dns_resolver).and_then(move |addr| {
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

    fn connect_remote(dns_resolver: DnsResolver,
                      handle: Handle,
                      addr: Address,
                      forbidden_ip: Arc<HashSet<IpAddr>>)
                      -> BoxIoFuture<TcpStream> {
        trace!("Connecting to remote {}", addr);
        Box::new(TcpRelayServer::resolve_remote(dns_resolver, addr, forbidden_ip)
            .and_then(move |addr| TcpStream::connect(&addr, &handle)))
    }

    pub fn handle_client(handle: &Handle,
                         dns_resolver: DnsResolver,
                         s: TcpStream,
                         svr_cfg: Arc<ServerConfig>,
                         forbidden_ip: Arc<HashSet<IpAddr>>)
                         -> io::Result<()> {
        let peer_addr = try!(s.peer_addr());
        trace!("Got connection from {}", peer_addr);

        let cloned_handle = handle.clone();

        let fut = TcpRelayServer::handshake(s, svr_cfg).and_then(move |(r, addr, w_fut)| {
            info!("Connecting {}", addr);
            let cloned_addr = addr.clone();
            TcpRelayServer::connect_remote(dns_resolver, cloned_handle.clone(), addr, forbidden_ip)
                .and_then(move |svr_s| {
                    let (svr_r, svr_w) = svr_s.split();
                    tunnel(cloned_addr,
                           copy(r, svr_w),
                           w_fut.and_then(|w| copy(svr_r, w)))
                })
        });

        handle.spawn(fut.then(|res| {
            match res {
                Ok(..) => Ok(()),
                Err(err) => {
                    error!("Failed to handle client: {}", err);
                    Err(())
                }
            }
        }));

        Ok(())
    }

    /// Runs the server
    pub fn run(config: Arc<Config>, handle: Handle) -> Box<Future<Item = (), Error = io::Error>> {
        let dns_resolver = DnsResolver::new(config.dns_cache_capacity);

        let mut fut: Option<Box<Future<Item = (), Error = io::Error>>> = None;

        let ref forbidden_ip = config.forbidden_ip;
        let forbidden_ip = Arc::new(forbidden_ip.clone());

        for svr_cfg in &config.server {
            let listener = {
                let addr = &svr_cfg.addr;
                let addr = addr.listen_addr();
                let listener = TcpListener::bind(addr, &handle).unwrap();
                trace!("ShadowSocks TCP Listening on {}", addr);
                listener
            };

            let svr_cfg = Arc::new(svr_cfg.clone());
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
                    TcpRelayServer::handle_client(&handle, dns_resolver, socket, server_cfg, forbidden_ip)
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
}
