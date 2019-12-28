//! HTTP Proxy client server

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
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
        loadbalancing::server::{ping, LoadBalancer, PingBalancer},
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
                super::proxy_server_handshake(stream, svr_cfg.clone(), &addr).await
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
                        super::proxy_server_handshake(stream, svr_cfg.clone(), &addr).await
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
    let port = match uri.port_u16() {
        Some(p) => p,
        None => {
            match uri.scheme_str() {
                None => 80, // Assume it is http
                Some("http") => 80,
                Some("https") => 443,
                _ => return None, // Not supported
            }
        }
    };

    match uri.host() {
        None => None,
        Some(host_str) => match host_str.parse::<IpAddr>() {
            Ok(ip) => Some(Address::from(SocketAddr::new(ip, port))),
            Err(..) => Some(Address::DomainNameAddress(host_str.to_owned(), port)),
        },
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
    svr_cfg: Arc<ServerConfig>,
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
    svr_cfg: Arc<ServerConfig>,
    client_addr: SocketAddr,
    client: ShadowSocksClient,
) -> Result<Response<Body>, io::Error> {
    if Method::CONNECT == req.method() {
        // Establish a TCP tunnel
        // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

        match host_addr(req.uri()) {
            Some(addr) => {
                debug!("CONNECT {}", addr);

                // Connect to Shadowsocks' remote
                //
                // FIXME: What STATUS should I return for connection error?
                let stream = super::connect_proxy_server(&*context, &*svr_cfg).await?;
                let stream = super::proxy_server_handshake(stream, svr_cfg.clone(), &addr).await?;

                debug!(
                    "CONNECT relay connected {} <-> {} ({})",
                    client_addr,
                    svr_cfg.addr(),
                    addr
                );

                // Upgrade to a TCP tunnel
                //
                // Note: only after client received an empty body with STATUS_OK can the
                // connection be upgraded, so we can't return a response inside
                // `on_upgrade` future.
                tokio::spawn(async move {
                    match req.into_body().on_upgrade().await {
                        Ok(upgraded) => {
                            trace!(
                                "CONNECT tunnel upgrade success, {} <-> {} ({})",
                                client_addr,
                                svr_cfg.addr(),
                                addr
                            );

                            establish_connect_tunnel(upgraded, stream, svr_cfg, client_addr, addr).await
                        }
                        Err(e) => {
                            error!(
                                "Failed to upgrade TCP tunnel {} <-> {} ({}), error: {}",
                                client_addr,
                                svr_cfg.addr(),
                                addr,
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
            }
            None => {
                error!("HTTP CONNECT URI is not a valid address. URI: {}", req.uri());

                let mut resp = Response::new(Body::from("CONNECT URI must be a valid Address"));
                *resp.status_mut() = StatusCode::BAD_REQUEST;

                Ok(resp)
            }
        }
    } else {
        let method = req.method().clone();

        let host = match host_addr(req.uri()) {
            None => {
                error!("HTTP {} URI is not a valid address. URI: {}", method, req.uri());

                let mut resp = Response::new(Body::from("URI must be a valid Address"));
                *resp.status_mut() = StatusCode::BAD_REQUEST;

                return Ok(resp);
            }
            Some(h) => h,
        };

        debug!("HTTP {} {}", method, host);

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

/// Starts a TCP local server with HTTP proxy protocol
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = *context.config().local.as_ref().expect("Missing local config");

    let mut servers = PingBalancer::new(context.clone(), ping::ServerType::Tcp).await;

    let mut server_clients = HashMap::new();

    // Create HTTP clients for each remote servers
    for svr_cfg in servers.servers() {
        let addr_str = svr_cfg.addr().to_string();
        let client = Client::builder().build::<_, Body>(ShadowSocksConnector::new(context.clone(), svr_cfg));
        server_clients.insert(addr_str, client);
    }

    let make_service = make_service_fn(|socket: &AddrStream| {
        let client_addr = socket.remote_addr();
        let svr_cfg = servers.pick_server();
        let context = context.clone();

        // Keep connections for clients
        let addr_str = svr_cfg.addr().to_string();
        let client = server_clients.get(&addr_str).unwrap().clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                server_dispatch(context.clone(), req, svr_cfg.clone(), client_addr, client.clone())
            }))
        }
    });

    let server = Server::bind(&local_addr).serve(make_service);

    let actual_local_addr = server.local_addr();

    info!("ShadowSocks HTTP Listening on {}", actual_local_addr);

    if let Err(err) = server.await {
        use std::io::{Error, ErrorKind};

        error!("Hyper Server error: {}", err);
        return Err(Error::new(ErrorKind::Other, err));
    }

    Ok(())
}
