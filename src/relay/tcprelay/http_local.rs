//! HTTP Proxy client server

use std::{
    convert::Infallible,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{self, Poll},
};

use futures::{
    future,
    future::{BoxFuture, Either},
    FutureExt,
};
use hyper::{
    client::connect::{Connected, Connection},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body,
    Client,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
    Uri,
};
use log::{debug, error, info, trace};
use pin_project::pin_project;
use tokio;
use tower;

use super::{CryptoStream, STcpStream};
use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{
        loadbalancing::server::{LoadBalancer, PingBalancer, PingServer, PingServerType},
        socks5::Address,
    },
};

#[derive(Clone)]
struct ShadowSocksConnector {
    context: SharedContext,
    svr_cfg: Arc<ServerConfig>,
}

impl ShadowSocksConnector {
    fn new(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> ShadowSocksConnector {
        ShadowSocksConnector { context, svr_cfg }
    }
}

impl tower::Service<Address> for ShadowSocksConnector {
    type Error = io::Error;
    type Future = ShadowSocksConnecting;
    type Response = CryptoStream<STcpStream>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, addr: Address) -> Self::Future {
        let svr_cfg = self.svr_cfg.clone();
        let context = self.context.clone();

        ShadowSocksConnecting {
            fut: async move {
                let stream = super::connect_proxy_server(&*context, &*svr_cfg).await?;
                super::proxy_server_handshake(&*context, stream, &*svr_cfg, &addr).await
            }
            .boxed(),
        }
    }
}

impl tower::Service<Uri> for ShadowSocksConnector {
    type Error = io::Error;
    type Future = ShadowSocksConnecting;
    type Response = CryptoStream<STcpStream>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let svr_cfg = self.svr_cfg.clone();
        let context = self.context.clone();

        ShadowSocksConnecting {
            fut: async move {
                match host_addr(&dst) {
                    None => {
                        use std::io::{Error, ErrorKind};

                        error!("HTTP target URI must be a valid address, but found: {}", dst);

                        let err = Error::new(ErrorKind::Other, "URI must be a valid Address");
                        Err(err)
                    }
                    Some(addr) => {
                        let stream = super::connect_proxy_server(&*context, &*svr_cfg).await?;
                        super::proxy_server_handshake(&*context, stream, &*svr_cfg, &addr).await
                    }
                }
            }
            .boxed(),
        }
    }
}

#[pin_project]
struct ShadowSocksConnecting {
    #[pin]
    fut: BoxFuture<'static, io::Result<CryptoStream<STcpStream>>>,
}

impl Future for ShadowSocksConnecting {
    type Output = io::Result<CryptoStream<STcpStream>>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

fn host_addr(uri: &Uri) -> Option<Address> {
    match uri.authority() {
        None => None,
        Some(authority) => {
            // NOTE: Authority may include authentication info (user:password)
            // Although it is already deprecated, but some very old application may still depending on it
            //
            // But ... We won't be compatible with it. :)

            // Check if URI has port
            match authority.port_u16() {
                Some(port) => {
                    // Well, it has port!
                    // 1. Maybe authority is a SocketAddr (127.0.0.1:1234, [::1]:1234)
                    // 2. Otherwise, it must be a domain name (google.com:443)

                    match authority.as_str().parse::<SocketAddr>() {
                        Ok(saddr) => Some(Address::from(saddr)),
                        Err(..) => Some(Address::DomainNameAddress(authority.host().to_owned(), port)),
                    }
                }
                None => {
                    // Ok, we don't have port
                    // 1. IPv4 Address 127.0.0.1
                    // 2. IPv6 Address: https://tools.ietf.org/html/rfc2732 , [::1]
                    // 3. Domain name

                    // Uses default port
                    let port = match uri.scheme_str() {
                        None => 80, // Assume it is http
                        Some("http") => 80,
                        Some("https") => 443,
                        _ => return None, // Not supported
                    };

                    // RFC2732 indicates that IPv6 address should be wrapped in [ and ]
                    let authority_str = authority.as_str();
                    if authority_str.starts_with('[') && authority_str.ends_with(']') {
                        // Must be a IPv6 address
                        let addr = authority_str.trim_start_matches('[').trim_end_matches(']');
                        match addr.parse::<IpAddr>() {
                            Ok(a) => Some(Address::from(SocketAddr::new(a, port))),
                            // Ignore invalid IPv6 address
                            Err(..) => None,
                        }
                    } else {
                        // Maybe it is a IPv4 address, or a non-standard IPv6
                        match authority_str.parse::<IpAddr>() {
                            Ok(a) => Some(Address::from(SocketAddr::new(a, port))),
                            // Should be a domain name, or a invalid IP address.
                            // Let DNS deal with it.
                            Err(..) => Some(Address::DomainNameAddress(authority_str.to_owned(), port)),
                        }
                    }
                }
            }
        }
    }
}

impl Connection for CryptoStream<STcpStream> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

async fn establish_connect_tunnel(
    upgraded: Upgraded,
    mut stream: CryptoStream<STcpStream>,
    svr_cfg: &ServerConfig,
    client_addr: SocketAddr,
    addr: Address,
) {
    use tokio::io::{copy, split};

    let (mut r, mut w) = split(upgraded);
    let (mut svr_r, mut svr_w) = stream.split();

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    debug!(
        "CONNECT relay established {} <-> {} ({})",
        client_addr,
        svr_cfg.addr(),
        addr
    );

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!("CONNECT relay {} -> {} ({}) closed", client_addr, svr_cfg.addr(), addr),
        Either::Left((Err(err), _)) => trace!(
            "CONNECT relay {} -> {} ({}) closed with error {:?}",
            client_addr,
            svr_cfg.addr(),
            addr,
            err,
        ),
        Either::Right((Ok(..), _)) => trace!("CONNECT relay {} <- {} ({}) closed", client_addr, svr_cfg.addr(), addr),
        Either::Right((Err(err), _)) => trace!(
            "CONNECT relay {} <- {} ({}) closed with error {:?}",
            client_addr,
            svr_cfg.addr(),
            addr,
            err,
        ),
    }

    debug!("CONNECT relay {} <-> {} ({}) closed", client_addr, svr_cfg.addr(), addr);
}

type ShadowSocksClient = Client<ShadowSocksConnector>;

async fn server_dispatch(
    context: SharedContext,
    req: Request<Body>,
    svr_score: Arc<ServerScore>,
    client_addr: SocketAddr,
    client: ShadowSocksClient,
) -> Result<Response<Body>, io::Error> {
    // Parse URI
    //
    // Proxy request URI must contains a host
    let host = match host_addr(req.uri()) {
        None => {
            error!("HTTP {} URI is not a valid address. URI: {}", req.method(), req.uri());

            let mut resp = Response::new(Body::from("URI must be a valid Address"));
            *resp.status_mut() = StatusCode::BAD_REQUEST;

            return Ok(resp);
        }
        Some(h) => h,
    };

    if Method::CONNECT == req.method() {
        // Establish a TCP tunnel
        // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

        debug!("HTTP CONNECT {}", host);

        // Connect to Shadowsocks' remote
        //
        // FIXME: What STATUS should I return for connection error?
        let stream = {
            let svr_cfg = svr_score.server_config();

            let stream = super::connect_proxy_server(&*context, svr_cfg).await?;
            super::proxy_server_handshake(&*context, stream, svr_cfg, &host).await?
        };

        debug!(
            "CONNECT relay connected {} <-> {} ({})",
            client_addr,
            svr_score.server_config().addr(),
            host
        );

        // Upgrade to a TCP tunnel
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        tokio::spawn(async move {
            let svr_cfg = svr_score.server_config();

            match req.into_body().on_upgrade().await {
                Ok(upgraded) => {
                    trace!(
                        "CONNECT tunnel upgrade success, {} <-> {} ({})",
                        client_addr,
                        svr_cfg.addr(),
                        host
                    );

                    establish_connect_tunnel(upgraded, stream, svr_cfg, client_addr, host).await
                }
                Err(e) => {
                    error!(
                        "Failed to upgrade TCP tunnel {} <-> {} ({}), error: {}",
                        client_addr,
                        svr_cfg.addr(),
                        host,
                        e
                    );
                }
            }
        });

        let resp = Response::builder()
            .header("Proxy-Agent", format!("ShadowSocks/{}", crate::VERSION))
            .body(Body::empty())
            .unwrap();

        Ok(resp)
    } else {
        let method = req.method().clone();

        debug!("HTTP {} {}", method, host);

        let svr_cfg = svr_score.server_config();

        let res = match client.request(req).await {
            Ok(res) => res,
            Err(err) => {
                error!(
                    "HTTP {} {} <-> {} ({}) relay failed, error: {}",
                    method,
                    client_addr,
                    svr_cfg.addr(),
                    host,
                    err
                );

                let mut resp = Response::new(Body::from(format!("Relay failed to {}", host)));
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                return Ok(resp);
            }
        };

        debug!(
            "HTTP {} relay {} <-> {} ({}) finished",
            method,
            client_addr,
            svr_cfg.addr(),
            host
        );

        Ok(res)
    }
}

type ShadowSocksHttpClient = Client<ShadowSocksConnector, Body>;

struct ServerScore {
    svr_cfg: Arc<ServerConfig>,
    score: AtomicU64,
    client: ShadowSocksHttpClient,
}

impl ServerScore {
    fn new(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> Arc<ServerScore> {
        let s = ServerScore {
            svr_cfg: svr_cfg.clone(),
            score: AtomicU64::new(0),
            // Create HTTP clients for each remote servers
            // It may reuse keep-alive connections
            client: Client::builder().build::<_, Body>(ShadowSocksConnector::new(context, svr_cfg)),
        };
        Arc::new(s)
    }
}

impl PingServer for ServerScore {
    fn server_config(&self) -> &ServerConfig {
        &*self.svr_cfg
    }

    fn score(&self) -> u64 {
        self.score.load(Ordering::Acquire)
    }

    fn set_score(&self, score: u64) {
        self.score.store(score, Ordering::Release);
    }
}

/// Starts a TCP local server with HTTP proxy protocol
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local.as_ref().expect("Missing local config");
    let bind_addr = local_addr.bind_addr(&*context).await?;

    let servers = context
        .config()
        .server
        .iter()
        .map(|sc| ServerScore::new(context.clone(), Arc::new(sc.clone())))
        .collect();
    let mut servers = PingBalancer::new(context.clone(), servers, PingServerType::Tcp).await;

    let make_service = make_service_fn(|socket: &AddrStream| {
        let client_addr = socket.remote_addr();
        let svr_score = servers.pick_server();
        let context = context.clone();

        // Keep connections for clients
        let client = svr_score.client.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                server_dispatch(context.clone(), req, svr_score.clone(), client_addr, client.clone())
            }))
        }
    });

    let server = Server::bind(&bind_addr).serve(make_service);
    info!("ShadowSocks HTTP Listening on {}", server.local_addr());

    if let Err(err) = server.await {
        use std::io::{Error, ErrorKind};

        error!("Hyper Server error: {}", err);
        return Err(Error::new(ErrorKind::Other, err));
    }

    Ok(())
}
