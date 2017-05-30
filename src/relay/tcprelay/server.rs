//! Relay for TCP server that running on the server side

use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::time::Duration;
use std::net::IpAddr;

use config::ServerConfig;

use relay::socks5::Address;
use relay::{BoxIoFuture, boxed_future};
use relay::dns_resolver::resolve;
use relay::tcprelay::crypto_io::{EncryptedWrite, DecryptedRead};
use relay::Context;

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::io::{ReadHalf, WriteHalf};
use tokio_io::AsyncRead;

use super::{tunnel, proxy_handshake, DecryptedHalf, EncryptedHalfFut, try_timeout};

/// Context for doing handshake with client
pub struct TcpRelayClientHandshake {
    s: TcpStream,
    svr_cfg: Rc<ServerConfig>,
}

impl TcpRelayClientHandshake {
    /// Doing handshake with client
    pub fn handshake(self) -> BoxIoFuture<TcpRelayClientPending> {
        let TcpRelayClientHandshake { s, svr_cfg } = self;

        let timeout = *svr_cfg.timeout();
        let fut = proxy_handshake(s, svr_cfg).and_then(move |(r_fut, w_fut)| {
            r_fut
                .and_then(move |r| {
                              let fut = Address::read_from(r).map_err(|_| {
                                                                          io::Error::new(io::ErrorKind::Other,
                                                                                         "failed to decode Address, may be wrong method or key")
                                                                      });
                              Context::with(|ctx| try_timeout(fut, timeout, ctx.handle()))
                          })
                .map(move |(r, addr)| {
                         TcpRelayClientPending {
                             r: r,
                             addr: addr,
                             w: w_fut,
                             timeout: timeout,
                         }
                     })
        });
        boxed_future(fut)
    }
}

/// Context for connecting remote
pub struct TcpRelayClientPending {
    r: DecryptedHalf,
    addr: Address,
    w: EncryptedHalfFut,
    timeout: Option<Duration>,
}

impl TcpRelayClientPending {
    /// Resolve Address to SocketAddr
    fn resolve_address(addr: Address, timeout: Option<Duration>) -> BoxIoFuture<SocketAddr> {
        match addr {
            Address::SocketAddress(addr) => Box::new(futures::finished(addr)),
            Address::DomainNameAddress(dname, port) => {
                let fut = Context::with(|ctx| {
                    let h = ctx.handle();
                    try_timeout(resolve(&dname[..], h), timeout, h).and_then(move |ipaddr| {
                                                                                 Ok(match ipaddr {
                                                                                        IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                                                                                        IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                                                                                    })
                                                                             })
                });
                Box::new(fut)
            }
        }
    }

    /// Resolve remote address to SocketAddr
    /// Report failure if the SocketAddr is forbidden by `forbidden_ip`
    fn resolve_remote(addr: Address, timeout: Option<Duration>) -> BoxIoFuture<SocketAddr> {
        let fut = TcpRelayClientPending::resolve_address(addr, timeout).and_then(move |addr| {
            let ipaddr = match addr {
                SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
                SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
            };

            Context::with(|ctx| {
                let config = ctx.config();
                let forbidden_ip = &config.forbidden_ip;
                if forbidden_ip.contains(&ipaddr) {
                    info!("{} has been forbidden", ipaddr);
                    let err = io::Error::new(io::ErrorKind::Other, "Forbidden IP");
                    Err(err)
                } else {
                    Ok(addr)
                }
            })
        });
        Box::new(fut)
    }

    /// Connect to the remote server
    fn connect_remote(addr: Address, timeout: Option<Duration>) -> BoxIoFuture<TcpStream> {
        info!("Connecting to remote {}", addr);
        Box::new(TcpRelayClientPending::resolve_remote(addr, timeout).and_then(move |addr| {
                                                                                   Context::with(|ctx| {
                                                                                                     try_timeout(TcpStream::connect(&addr, ctx.handle()),
                                                                                                                 timeout,
                                                                                                                 ctx.handle())
                                                                                                 })
                                                                               }))
    }

    /// Connect to the remote server
    pub fn connect(self) -> BoxIoFuture<TcpRelayClientConnected> {
        let addr = self.addr.clone();
        let client_pair = (self.r, self.w);
        let timeout = self.timeout;
        let fut = TcpRelayClientPending::connect_remote(self.addr, self.timeout);
        let fut = fut.map(move |stream| {
                              TcpRelayClientConnected {
                                  server: stream.split(),
                                  client: client_pair,
                                  addr: addr,
                                  timeout: timeout,
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
}

impl TcpRelayClientConnected {
    /// Establish tunnel
    pub fn tunnel(self) -> BoxIoFuture<()> {
        let (svr_r, svr_w) = self.server;
        let (r, w_fut) = self.client;
        let timeout = self.timeout;

        tunnel(self.addr,
               r.copy_timeout_opt(svr_w, self.timeout),
               w_fut.and_then(move |w| w.copy_timeout_opt(svr_r, timeout)))
    }
}

/// Runs the server
pub fn run() -> Box<Future<Item = (), Error = io::Error>> {
    let mut fut: Option<Box<Future<Item = (), Error = io::Error>>> = None;

    Context::with(|ctx| {
        let config = ctx.config();

        for svr_cfg in &config.server {
            let listener = {
                let addr = svr_cfg.addr();
                let addr = addr.listen_addr();

                let listener = TcpListener::bind(&addr, ctx.handle()).unwrap_or_else(|err| panic!("Failed to listen, {}", err));

                info!("ShadowSocks TCP Listening on {}", addr);
                listener
            };

            let svr_cfg = Rc::new(svr_cfg.clone());
            let listening = listener
                .incoming()
                .for_each(move |(socket, addr)| {
                    let server_cfg = svr_cfg.clone();

                    trace!("Got connection, addr: {}", addr);
                    trace!("Picked proxy server: {:?}", server_cfg);

                    let client = TcpRelayClientHandshake {
                        s: socket,
                        svr_cfg: server_cfg,
                    };

                    let fut = client
                        .handshake()
                        .and_then(|c| c.connect())
                        .and_then(|c| c.tunnel())
                        .map_err(move |err| {
                                     error!("Failed to handle client ({}): {}", addr, err);
                                 });

                    Context::with(|ctx| ctx.handle().spawn(fut));
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

    })
}
