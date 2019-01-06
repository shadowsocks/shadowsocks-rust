//! Relay for TCP server that running on the server side

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use relay::{
    boxed_future,
    dns_resolver::resolve,
    socks5::Address,
    tcprelay::crypto_io::{DecryptedRead, EncryptedWrite},
};

use context::SharedContext;

use futures::{
    self,
    stream::{futures_unordered, Stream},
    Future,
};

use tokio::{
    self,
    net::{TcpListener, TcpStream},
};
use tokio_io::{
    io::{ReadHalf, WriteHalf},
    AsyncRead,
};

use super::{
    context::{SharedTcpServerContext, TcpServerContext},
    monitor::TcpMonStream,
    proxy_handshake,
    try_timeout,
    tunnel,
    DecryptedHalf,
    EncryptedHalf,
    TcpStreamConnect,
};

/// Context for doing handshake with client
pub struct TcpRelayClientHandshake {
    s: TcpMonStream,
    svr_context: SharedTcpServerContext,
}

impl TcpRelayClientHandshake {
    #[inline]
    fn error_handshake(peer_addr: SocketAddr) -> io::Error {
        io::Error::new(
            ErrorKind::Other,
            format!(
                "failed to decode Address, may be wrong method or key, peer: {}",
                peer_addr
            ),
        )
    }

    /// Doing handshake with client
    pub fn handshake(
        self,
    ) -> impl Future<
        Item = TcpRelayClientPending<
            impl Future<Item = EncryptedHalf<TcpMonStream>, Error = io::Error> + Send + 'static,
        >,
        Error = io::Error,
    > + Send {
        let TcpRelayClientHandshake { s, svr_context } = self;

        futures::lazy(move || s.peer_addr().map(|p| (s, p))).and_then(|(s, peer_addr)| {
            debug!("Handshaking with peer {}", peer_addr);

            let timeout = svr_context.svr_cfg().timeout();
            proxy_handshake(s, svr_context.svr_cfg().clone()).and_then(move |(r_fut, w_fut)| {
                r_fut
                    .and_then(move |r| {
                        let fut =
                            Address::read_from(r).map_err(move |_| TcpRelayClientHandshake::error_handshake(peer_addr));
                        try_timeout(fut, timeout)
                    })
                    .map(move |(r, addr)| TcpRelayClientPending {
                        r: r,
                        addr: addr,
                        w: w_fut,
                        timeout: timeout,
                        svr_context: svr_context,
                    })
            })
        })
    }
}

/// Context for connecting remote
pub struct TcpRelayClientPending<E>
where
    E: Future<Item = EncryptedHalf<TcpMonStream>, Error = io::Error> + Send + 'static,
{
    r: DecryptedHalf<TcpMonStream>,
    addr: Address,
    w: E,
    timeout: Option<Duration>,
    svr_context: SharedTcpServerContext,
}

/// Connect to the remote server
#[inline]
fn connect_remote(
    context: SharedContext,
    addr: Address,
    timeout: Option<Duration>,
) -> impl Future<Item = TcpStream, Error = io::Error> + Send {
    debug!("Connecting to remote {}", addr);

    match addr {
        Address::SocketAddress(saddr) => {
            if context.config().forbidden_ip.contains(&saddr.ip()) {
                let err = io::Error::new(
                    ErrorKind::Other,
                    format!("{} is forbidden, failed to connect {}", saddr.ip(), saddr),
                );
                return boxed_future(futures::done(Err(err)));
            }

            let conn = TcpStream::connect(&saddr);
            let fut = try_timeout(conn, timeout);
            boxed_future(fut)
        }
        Address::DomainNameAddress(dname, port) => {
            let fut = {
                try_timeout(resolve(context, dname.as_str(), port, true), timeout).and_then(move |addrs| {
                    let conn = TcpStreamConnect::new(addrs.into_iter());
                    try_timeout(conn, timeout)
                })
            };
            boxed_future(fut)
        }
    }
}

impl<E> TcpRelayClientPending<E>
where
    E: Future<Item = EncryptedHalf<TcpMonStream>, Error = io::Error> + Send + 'static,
{
    /// Connect to the remote server
    pub fn connect(
        self,
    ) -> impl Future<
        Item = TcpRelayClientConnected<
            impl Future<Item = EncryptedHalf<TcpMonStream>, Error = io::Error> + Send + 'static,
        >,
        Error = io::Error,
    > + Send {
        let client_pair = (self.r, self.w);
        let timeout = self.timeout;
        connect_remote(self.svr_context.context().clone(), self.addr, self.timeout).map(move |stream| {
            TcpRelayClientConnected {
                server: stream.split(),
                client: client_pair,
                timeout: timeout,
            }
        })
    }
}

/// Context for extablishing tunnel
pub struct TcpRelayClientConnected<E>
where
    E: Future<Item = EncryptedHalf<TcpMonStream>, Error = io::Error> + Send + 'static,
{
    server: (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
    client: (DecryptedHalf<TcpMonStream>, E),
    timeout: Option<Duration>,
}

impl<E> TcpRelayClientConnected<E>
where
    E: Future<Item = EncryptedHalf<TcpMonStream>, Error = io::Error> + Send + 'static,
{
    /// Establish tunnel
    #[inline]
    pub fn tunnel(self) -> impl Future<Item = (), Error = io::Error> + Send {
        let (svr_r, svr_w) = self.server;
        let (r, w_fut) = self.client;
        let timeout = self.timeout;

        tunnel(
            r.copy_timeout_opt(svr_w, self.timeout),
            w_fut.and_then(move |w| w.copy_timeout_opt(svr_r, timeout)),
        )
    }
}

fn handle_client(svr_context: SharedTcpServerContext, socket: TcpStream) -> impl Future<Item = (), Error = ()> + Send {
    let socket = TcpMonStream::new(svr_context.clone(), socket);

    if let Err(err) = socket.set_keepalive(svr_context.svr_cfg().timeout()) {
        error!("Failed to set keep alive: {:?}", err);
    }

    if svr_context.context().config().no_delay {
        if let Err(err) = socket.set_nodelay(true) {
            error!("Failed to set no delay: {:?}", err);
        }
    }

    futures::lazy(move || match socket.peer_addr() {
        Ok(addr) => Ok((socket, addr)),
        Err(err) => {
            error!("Failed to get peer_addr after accept: {}", err);
            Err(())
        }
    })
    .and_then(move |(socket, addr)| {
        trace!("Got connection, addr: {}", addr);
        trace!("Picked proxy server: {:?}", svr_context.svr_cfg());

        let client = TcpRelayClientHandshake {
            s: socket,
            svr_context: svr_context,
        };

        client
            .handshake()
            .and_then(|c| c.connect())
            .and_then(|c| c.tunnel())
            .map_err(move |err| {
                error!("Failed to handle client ({}): {}", addr, err);
            })
    })
}

/// Runs the server
pub fn run(context: SharedContext) -> impl Future<Item = (), Error = io::Error> + Send {
    let mut vec_fut = Vec::with_capacity(context.config().server.len());

    for svr_cfg in &context.config().server {
        let listener = {
            let addr = svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr());
            let addr = addr.listen_addr();

            let listener = TcpListener::bind(&addr).unwrap_or_else(|err| panic!("Failed to listen, {}", err));

            info!("ShadowSocks TCP Listening on {}", addr);
            listener
        };

        let svr_cfg = Arc::new(svr_cfg.clone());
        let context = context.clone();
        let svr_context = TcpServerContext::new(context.clone(), svr_cfg.clone());

        struct CloseGuard(SharedTcpServerContext);
        impl Drop for CloseGuard {
            fn drop(&mut self) {
                self.0.close();
            }
        }

        let close_guard = CloseGuard(svr_context.clone());

        let listening = listener
            .incoming()
            .for_each(move |socket| {
                let svr_context = svr_context.clone();
                tokio::spawn(handle_client(svr_context, socket));
                Ok(())
            })
            .map_err(|err| {
                error!("Server run failed: {}", err);
                err
            })
            .then(move |r| {
                // Close the context to ensure reporting Future is terminated
                drop(close_guard);
                r
            });

        vec_fut.push(boxed_future(listening));
    }

    futures_unordered(vec_fut).into_future().then(|res| match res {
        Ok(..) => {
            error!("One of TCP servers exited unexpectly without error");
            let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
            Err(err)
        }
        Err((err, ..)) => {
            error!("One of TCP servers exited unexpectly with error {}", err);
            Err(err)
        }
    })
}
