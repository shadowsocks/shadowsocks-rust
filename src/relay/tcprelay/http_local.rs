//! HTTP Proxy client server

use std::{convert::Infallible, io, net::SocketAddr, sync::Arc};

use futures::{future, future::Either};
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
    Uri,
};
use log::{debug, error, info, trace};
use tokio;

use super::{CryptoStream, STcpStream};
use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{
        loadbalancing::server::{ping, LoadBalancer, PingBalancer},
        socks5::Address,
    },
};

fn host_addr(uri: &Uri) -> Option<Address> {
    uri.authority().and_then(|auth| auth.as_str().parse().ok())
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

async fn server_dispatch(
    context: SharedContext,
    req: Request<Body>,
    svr_cfg: Arc<ServerConfig>,
    client_addr: SocketAddr,
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
        unimplemented!();
    }
}

/// Starts a TCP local server with HTTP proxy protocol
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = *context.config().local.as_ref().expect("Missing local config");

    let mut servers = PingBalancer::new(context.clone(), ping::ServerType::Tcp).await;

    let make_service = make_service_fn(|socket: &AddrStream| {
        let client_addr = socket.remote_addr();
        let svr_cfg = servers.pick_server();
        let context = context.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                server_dispatch(context.clone(), req, svr_cfg.clone(), client_addr)
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
