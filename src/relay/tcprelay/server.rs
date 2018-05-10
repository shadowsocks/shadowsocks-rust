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
    pub fn handshake(self) -> IoFuture<TcpRelayClientPending> {
        let TcpRelayClientHandshake { s, svr_cfg, config } = self;

        let fut = futures::lazy(move || s.peer_addr().map(|p| (s, p))).and_then(|(s, peer_addr)| {
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
    config: Arc<Config>,
}

impl TcpRelayClientPending {
    /// Connect to the remote server
    #[inline]
    fn connect_remote(config: Arc<Config>, addr: Address, timeout: Option<Duration>) -> IoFuture<TcpStream> {
        debug!("Connecting to remote {}", addr);

        match addr {
            Address::SocketAddress(saddr) => {
                if config.forbidden_ip.contains(&saddr.ip()) {
                    let err = io::Error::new(ErrorKind::Other,
                                             format!("{} is forbidden, failed to connect {}", saddr.ip(), saddr));
                    return boxed_future(futures::done(Err(err)));
                }

                let conn = TcpStream::connect(&saddr);
                try_timeout(conn, timeout)
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
    pub fn connect(self) -> IoFuture<TcpRelayClientConnected> {
        let addr = self.addr.clone();
        let client_pair = (self.r, self.w);
        let timeout = self.timeout;
        let fut = TcpRelayClientPending::connect_remote(self.config, self.addr, self.timeout);
        let fut = fut.map(move |stream| TcpRelayClientConnected { server: stream.split(),
                                                                  client: client_pair,
                                                                  addr: addr,
                                                                  timeout: timeout, });
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
    #[inline]
    pub fn tunnel(self) -> IoFuture<()> {
        let (svr_r, svr_w) = self.server;
        let (r, w_fut) = self.client;
        let timeout = self.timeout;

        tunnel(self.addr,
               r.copy_timeout_opt(svr_w, self.timeout),
               w_fut.and_then(move |w| w.copy_timeout_opt(svr_r, timeout)))
    }
}

/// Runs the server
pub fn run(config: Arc<Config>) -> IoFuture<()> {
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

                                              let addr = socket.peer_addr()?;

                                              trace!("Got connection, addr: {}", addr);
                                              trace!("Picked proxy server: {:?}", server_cfg);

                                              let client = TcpRelayClientHandshake { s: socket,
                                                                                     svr_cfg: server_cfg,
                                                                                     config: config.clone(), };

                                              let fut = client.handshake()
                                                              .and_then(|c| c.connect())
                                                              .and_then(|c| c.tunnel())
                                                              .map_err(move |err| {
                                                                           error!("Failed to handle client ({}): {}",
                                                                                  addr, err);
                                                                       });

                                              tokio::spawn(fut);
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
