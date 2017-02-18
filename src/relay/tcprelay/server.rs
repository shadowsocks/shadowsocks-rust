//! Relay for TCP server that running on the server side

use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::collections::HashSet;
use std::time::Duration;
use std::net::IpAddr;

use config::{Config, ServerConfig};

use relay::socks5::Address;
use relay::{BoxIoFuture, boxed_future};
use relay::dns_resolver::resolve;
use relay::tcprelay::crypto_io::{EncryptedWrite, DecryptedRead};

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::reactor::Handle;
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::io::{Io, ReadHalf, WriteHalf};

use net2::TcpBuilder;

use super::{tunnel, proxy_handshake, DecryptedHalf, EncryptedHalfFut, try_timeout};

/// Context for doing handshake with client
pub struct TcpRelayClientHandshake {
    handle: Handle,
    s: TcpStream,
    svr_cfg: Rc<ServerConfig>,
    forbidden_ip: Rc<HashSet<IpAddr>>,
}

impl TcpRelayClientHandshake {
    /// Doing handshake with client
    pub fn handshake(self) -> BoxIoFuture<TcpRelayClientPending> {
        let TcpRelayClientHandshake { handle, forbidden_ip, s, svr_cfg } = self;

        let timeout = *svr_cfg.timeout();
        let cloned_handle = handle.clone();
        let fut = proxy_handshake(s, svr_cfg, handle.clone()).and_then(move |(r_fut, w_fut)| {
            r_fut.and_then(move |r| {
                    let handle = cloned_handle;
                    try_timeout(Address::read_from(r).map_err(|_| {
                                    io::Error::new(io::ErrorKind::Other,
                                                   "failed to decode Address, may be wrong method or key")
                                }),
                                timeout,
                                &handle)
                })
                .map(move |(r, addr)| {
                    TcpRelayClientPending {
                        handle: handle,
                        r: r,
                        addr: addr,
                        w: w_fut,
                        forbidden_ip: forbidden_ip,
                        timeout: timeout,
                    }
                })
        });
        boxed_future(fut)
    }
}

/// Context for connecting remote
pub struct TcpRelayClientPending {
    handle: Handle,
    r: DecryptedHalf,
    addr: Address,
    w: EncryptedHalfFut,
    forbidden_ip: Rc<HashSet<IpAddr>>,
    timeout: Option<Duration>,
}

impl TcpRelayClientPending {
    /// Resolve Address to SocketAddr
    fn resolve_address(handle: Handle, addr: Address, timeout: Option<Duration>) -> BoxIoFuture<SocketAddr> {
        match addr {
            Address::SocketAddress(addr) => Box::new(futures::finished(addr)),
            Address::DomainNameAddress(dname, port) => {
                let fut = try_timeout(resolve(&dname[..], &handle), timeout, &handle).and_then(move |ipaddr| {
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
    fn resolve_remote(handle: Handle,
                      addr: Address,
                      forbidden_ip: Rc<HashSet<IpAddr>>,
                      timeout: Option<Duration>)
                      -> BoxIoFuture<SocketAddr> {
        let fut = TcpRelayClientPending::resolve_address(handle, addr, timeout).and_then(move |addr| {
            let ipaddr = match addr {
                SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
                SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
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
    fn connect_remote(handle: Handle,
                      addr: Address,
                      forbidden_ip: Rc<HashSet<IpAddr>>,
                      timeout: Option<Duration>)
                      -> BoxIoFuture<TcpStream> {
        info!("Connecting to remote {}", addr);
        Box::new(TcpRelayClientPending::resolve_remote(handle.clone(), addr, forbidden_ip, timeout)
            .and_then(move |addr| try_timeout(TcpStream::connect(&addr, &handle), timeout, &handle)))
    }

    /// Connect to the remote server
    pub fn connect(self) -> BoxIoFuture<TcpRelayClientConnected> {
        let addr = self.addr.clone();
        let client_pair = (self.r, self.w);
        let timeout = self.timeout;
        let handle = self.handle.clone();
        let fut = TcpRelayClientPending::connect_remote(self.handle, self.addr, self.forbidden_ip, self.timeout)
            .map(move |stream| {
                TcpRelayClientConnected {
                    server: stream.split(),
                    client: client_pair,
                    addr: addr,
                    timeout: timeout,
                    handle: handle,
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
    timeout: Option<Duration>,
    handle: Handle,
}

impl TcpRelayClientConnected {
    /// Establish tunnel
    pub fn tunnel(self) -> BoxIoFuture<()> {
        let (svr_r, svr_w) = self.server;
        let (r, w_fut) = self.client;
        let timeout = self.timeout;
        let handle = self.handle.clone();
        tunnel(self.addr,
               r.copy_timeout_opt(svr_w, self.timeout, self.handle),
               w_fut.and_then(move |w| w.copy_timeout_opt(svr_r, timeout, handle)))
    }
}

/// Runs the server
pub fn run(config: Rc<Config>, handle: Handle) -> Box<Future<Item = (), Error = io::Error>> {
    let mut fut: Option<Box<Future<Item = (), Error = io::Error>>> = None;

    let forbidden_ip = &config.forbidden_ip;
    let forbidden_ip = Rc::new(forbidden_ip.clone());

    for svr_cfg in &config.server {
        let listener = {
            let addr = svr_cfg.addr();
            let addr = addr.listen_addr();

            let tcp_builder = match *addr {
                    SocketAddr::V4(..) => TcpBuilder::new_v4(),
                    SocketAddr::V6(..) => TcpBuilder::new_v6(),
                }
                .unwrap_or_else(|err| panic!("Failed to create listener, {}", err));

            super::reuse_port(&tcp_builder)
                .and_then(|builder| builder.reuse_address(true))
                .and_then(|builder| builder.bind(addr))
                .unwrap_or_else(|err| panic!("Failed to bind {}, {}", addr, err));

            let listener = tcp_builder.listen(1024)
                .and_then(|l| TcpListener::from_listener(l, addr, &handle))
                .unwrap_or_else(|err| panic!("Failed to listen, {}", err));

            info!("ShadowSocks TCP Listening on {}", addr);
            listener
        };

        let svr_cfg = Rc::new(svr_cfg.clone());
        let handle = handle.clone();
        let forbidden_ip = forbidden_ip.clone();
        let listening = listener.incoming()
            .for_each(move |(socket, addr)| {
                let server_cfg = svr_cfg.clone();
                let forbidden_ip = forbidden_ip.clone();

                trace!("Got connection, addr: {}", addr);
                trace!("Picked proxy server: {:?}", server_cfg);

                let client = TcpRelayClientHandshake {
                    handle: handle.clone(),
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
