//! Relay for TCP server that running on the server side

use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use config::{Config, ServerConfig};

use relay::boxed_future;
use relay::dns_resolver::resolve;
use relay::socks5::Address;
use relay::tcprelay::crypto_io::{DecryptedRead, EncryptedWrite};

use futures::stream::Stream;
use futures::{self, Future};

use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_io::io::{ReadHalf, WriteHalf};
use tokio_io::{AsyncRead, IoFuture};

use super::{proxy_handshake, try_timeout, tunnel, DecryptedHalf, EncryptedHalfFut, TcpStreamConnect};

/// Context for doing handshake with client
pub struct TcpRelayClientHandshake {
    s: TcpStream,
    svr_cfg: Arc<ServerConfig>,
    config: Arc<Config>,
}

impl TcpRelayClientHandshake {
    /// Doing handshake with client
    pub fn handshake(self) -> impl Future<Item = TcpRelayClientPending, Error = io::Error> {
        let TcpRelayClientHandshake { s, svr_cfg, config } = self;

        futures::lazy(move || s.peer_addr().map(|p| (s, p))).and_then(|(s, peer_addr)| {
            debug!("Handshaking with peer {}", peer_addr);

            let timeout = *svr_cfg.timeout();
            proxy_handshake(s, svr_cfg).and_then(move |(r_fut, w_fut)| {
                r_fut.and_then(move |r| {
                                   let fut = Address::read_from(r).map_err(move |_| {
                                       io::Error::new(ErrorKind::Other,
                                       format!("failed to decode Address, may be wrong method or key, peer: {}",
                                               peer_addr))
                                   });
                                   try_timeout(fut, timeout)
                               })
                     .map(move |(r, addr)| TcpRelayClientPending { r: r,
                                                                   addr: addr,
                                                                   w: w_fut,
                                                                   timeout: timeout,
                                                                   config: config, })
            })
        })
    }
}

/// Context for connecting remote
pub struct TcpRelayClientPending {
    r: DecryptedHalf,
    addr: Address,
    w: EncryptedHalfFut,
    timeout: Option<Duration>,
    config: Arc<Config>,
}

impl TcpRelayClientPending {
    /// Connect to the remote server
    #[inline]
    fn connect_remote(config: Arc<Config>,
                      addr: Address,
                      timeout: Option<Duration>)
                      -> impl Future<Item = TcpStream, Error = io::Error> {
        debug!("Connecting to remote {}", addr);

        match addr {
            Address::SocketAddress(saddr) => {
                if config.forbidden_ip.contains(&saddr.ip()) {
                    let err = io::Error::new(ErrorKind::Other,
                                             format!("{} is forbidden, failed to connect {}", saddr.ip(), saddr));
                    return boxed_future(futures::done(Err(err)));
                }

                let conn = TcpStream::connect(&saddr);
                let fut = try_timeout(conn, timeout);
                boxed_future(fut)
            }
            Address::DomainNameAddress(dname, port) => {
                let fut = {
                    try_timeout(resolve(config, dname.as_str(), port, true), timeout).and_then(move |addrs| {
                        let conn = TcpStreamConnect::new(addrs.into_iter());
                        try_timeout(conn, timeout)
                    })
                };
                boxed_future(fut)
            }
        }
    }

    /// Connect to the remote server
    pub fn connect(self) -> impl Future<Item = TcpRelayClientConnected, Error = io::Error> + Send {
        let addr = self.addr.clone();
        let client_pair = (self.r, self.w);
        let timeout = self.timeout;
        TcpRelayClientPending::connect_remote(self.config, self.addr, self.timeout).map(move |stream| {
            TcpRelayClientConnected { server: stream.split(),
                                      client: client_pair,
                                      addr: addr,
                                      timeout: timeout, }
        })
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
    #[inline]
    pub fn tunnel(self) -> impl Future<Item = (), Error = io::Error> + Send {
        let (svr_r, svr_w) = self.server;
        let (r, w_fut) = self.client;
        let timeout = self.timeout;

        tunnel(self.addr,
               r.copy_timeout_opt(svr_w, self.timeout),
               w_fut.and_then(move |w| w.copy_timeout_opt(svr_r, timeout)))
    }
}

fn handle_client(server_cfg: Arc<ServerConfig>,
                 config: Arc<Config>,
                 socket: TcpStream)
                 -> impl Future<Item = (), Error = ()> + Send {
    futures::lazy(move || match socket.peer_addr() {
                      Ok(addr) => Ok((socket, addr)),
                      Err(err) => {
                          error!("Failed to get peer_addr after accept: {}", err);
                          Err(())
                      }
                  }).and_then(move |(socket, addr)| {
                                      trace!("Got connection, addr: {}", addr);
                                      trace!("Picked proxy server: {:?}", server_cfg);

                                      let client = TcpRelayClientHandshake { s: socket,
                                                                             svr_cfg: server_cfg,
                                                                             config: config, };

                                      client.handshake()
                                            .and_then(|c| c.connect())
                                            .and_then(|c| c.tunnel())
                                            .map_err(move |err| {
                                                         error!("Failed to handle client ({}): {}", addr, err);
                                                     })
                                  })
}

/// Runs the server
pub fn run(config: Arc<Config>) -> impl Future<Item = (), Error = io::Error> + Send {
    let mut fut: Option<IoFuture<()>> = None;

    for svr_cfg in &config.server {
        let listener = {
            let addr = svr_cfg.addr();
            let addr = addr.listen_addr();

            let listener = TcpListener::bind(&addr).unwrap_or_else(|err| panic!("Failed to listen, {}", err));

            info!("ShadowSocks TCP Listening on {}", addr);
            listener
        };

        let svr_cfg = Arc::new(svr_cfg.clone());
        let config = config.clone();
        let listening = listener.incoming()
                                .for_each(move |socket| {
                                              let server_cfg = svr_cfg.clone();
                                              let config = config.clone();
                                              tokio::spawn(handle_client(server_cfg, config, socket));
                                              Ok(())
                                          })
                                .map_err(|err| {
                                             error!("Server run failed: {}", err);
                                             err
                                         });

        fut = Some(match fut.take() {
                       Some(fut) => Box::new(fut.join(listening).map(|_| ())) as IoFuture<()>,
                       None => Box::new(listening) as IoFuture<()>,
                   })
    }

    fut.expect("Must have at least one server")
}
