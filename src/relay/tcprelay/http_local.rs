//! HTTP Proxy client server

use std::{
    convert::Infallible,
    future::Future,
    io,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    str::FromStr,
    task::{self, Poll},
};

use futures::{
    future,
    future::{BoxFuture, Either},
    FutureExt,
};
use http::uri::{Authority, Scheme};
use hyper::{
    client::connect::{Connected, Connection},
    header::HeaderValue,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body,
    Client,
    HeaderMap,
    Method,
    Request,
    Response,
    Server,
    StatusCode,
    Uri,
    Version,
};
use log::{debug, error, info, trace};
use pin_project::pin_project;

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{
            PingBalancer,
            ServerData,
            ServerType,
            SharedServerStatistic,
            SharedServerStatisticData,
        },
        socks5::Address,
    },
};

use super::ProxyStream;

#[derive(Clone)]
struct ShadowSocksConnector {
    context: SharedContext,
    svr_idx: usize,
    stat: SharedServerStatisticData,
}

impl ShadowSocksConnector {
    fn new(context: SharedContext, svr_idx: usize, stat: SharedServerStatisticData) -> ShadowSocksConnector {
        ShadowSocksConnector { context, svr_idx, stat }
    }
}

impl tower::Service<Uri> for ShadowSocksConnector {
    type Error = io::Error;
    type Future = ShadowSocksConnecting;
    type Response = ProxyStream;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let context = self.context.clone();
        let svr_idx = self.svr_idx;
        let stat = self.stat.clone();

        ShadowSocksConnecting {
            fut: async move {
                let svr_cfg = context.server_config(svr_idx);

                match host_addr(&dst) {
                    None => {
                        use std::io::Error;

                        error!("HTTP target URI must be a valid address, but found: {}", dst);

                        let err = Error::new(ErrorKind::Other, "URI must be a valid Address");
                        Err(err)
                    }
                    Some(addr) => {
                        match ProxyStream::connect_proxied(context.clone(), svr_cfg, &addr).await {
                            Ok(s) => Ok(s),
                            Err(err) => {
                                // Report failure to global statistic
                                stat.report_failure().await;
                                Err(err)
                            }
                        }
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
    fut: BoxFuture<'static, io::Result<ProxyStream>>,
}

impl Future for ShadowSocksConnecting {
    type Output = io::Result<ProxyStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

#[derive(Clone)]
struct DirectConnector {
    context: SharedContext,
}

impl DirectConnector {
    fn new(context: SharedContext) -> DirectConnector {
        DirectConnector { context }
    }
}

impl tower::Service<Uri> for DirectConnector {
    type Error = io::Error;
    type Future = DirectConnecting;
    type Response = ProxyStream;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let context = self.context.clone();

        DirectConnecting {
            fut: async move {
                match host_addr(&dst) {
                    None => {
                        use std::io::Error;

                        error!("HTTP target URI must be a valid address, but found: {}", dst);

                        let err = Error::new(ErrorKind::Other, "URI must be a valid Address");
                        Err(err)
                    }
                    Some(addr) => ProxyStream::connect_direct(context, &addr).await,
                }
            }
            .boxed(),
        }
    }
}

#[pin_project]
struct DirectConnecting {
    #[pin]
    fut: BoxFuture<'static, io::Result<ProxyStream>>,
}

impl Future for DirectConnecting {
    type Output = io::Result<ProxyStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

fn authority_addr(scheme_str: Option<&str>, authority: &Authority) -> Option<Address> {
    // RFC7230 indicates that we should ignore userinfo
    // https://tools.ietf.org/html/rfc7230#section-5.3.3

    // Check if URI has port
    let port = match authority.port_u16() {
        Some(port) => port,
        None => {
            match scheme_str {
                None => 80, // Assume it is http
                Some("http") => 80,
                Some("https") => 443,
                _ => return None, // Not supported
            }
        }
    };

    let host_str = authority.host();

    // RFC3986 indicates that IPv6 address should be wrapped in [ and ]
    // https://tools.ietf.org/html/rfc3986#section-3.2.2
    //
    // Example: [::1] without port
    if host_str.starts_with('[') && host_str.ends_with(']') {
        // Must be a IPv6 address
        let addr = &host_str[1..host_str.len() - 1];
        match addr.parse::<Ipv6Addr>() {
            Ok(a) => Some(Address::from(SocketAddr::new(IpAddr::V6(a), port))),
            // Ignore invalid IPv6 address
            Err(..) => None,
        }
    } else {
        // It must be a IPv4 address
        match host_str.parse::<Ipv4Addr>() {
            Ok(a) => Some(Address::from(SocketAddr::new(IpAddr::V4(a), port))),
            // Should be a domain name, or a invalid IP address.
            // Let DNS deal with it.
            Err(..) => Some(Address::DomainNameAddress(host_str.to_owned(), port)),
        }
    }
}

fn host_addr(uri: &Uri) -> Option<Address> {
    match uri.authority() {
        None => None,
        Some(authority) => authority_addr(uri.scheme_str(), authority),
    }
}

fn check_keep_alive(version: Version, headers: &HeaderMap<HeaderValue>, check_proxy: bool) -> bool {
    let mut conn_keep_alive = match version {
        Version::HTTP_10 => false,
        Version::HTTP_11 => true,
        _ => unimplemented!("HTTP Proxy only supports 1.0 and 1.1"),
    };

    if check_proxy {
        // Modern browers will send Proxy-Connection instead of Connection
        // for HTTP/1.0 proxies which blindly forward Connection to remote
        //
        // https://tools.ietf.org/html/rfc7230#appendix-A.1.2
        for value in headers.get_all("Proxy-Connection") {
            if let Ok(value) = value.to_str() {
                if value.eq_ignore_ascii_case("close") {
                    conn_keep_alive = false;
                } else {
                    for part in value.split(',') {
                        let part = part.trim();
                        if part.eq_ignore_ascii_case("keep-alive") {
                            conn_keep_alive = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Connection will replace Proxy-Connection
    //
    // But why client sent both Connection and Proxy-Connection? That's not standard!
    for value in headers.get_all("Connection") {
        if let Ok(value) = value.to_str() {
            if value.eq_ignore_ascii_case("close") {
                conn_keep_alive = false;
            } else {
                for part in value.split(',') {
                    let part = part.trim();

                    if part.eq_ignore_ascii_case("keep-alive") {
                        conn_keep_alive = true;
                        break;
                    }
                }
            }
        }
    }

    conn_keep_alive
}

fn clear_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    // Clear headers indicated by Connection and Proxy-Connection
    let mut extra_headers = Vec::new();

    for connection in headers.get_all("Connection") {
        if let Ok(conn) = connection.to_str() {
            if !conn.eq_ignore_ascii_case("close") {
                for header in conn.split(',') {
                    let header = header.trim();

                    if !header.eq_ignore_ascii_case("keep-alive") {
                        extra_headers.push(header.to_owned());
                    }
                }
            }
        }
    }

    for connection in headers.get_all("Proxy-Connection") {
        if let Ok(conn) = connection.to_str() {
            if !conn.eq_ignore_ascii_case("close") {
                for header in conn.split(',') {
                    let header = header.trim();

                    if !header.eq_ignore_ascii_case("keep-alive") {
                        extra_headers.push(header.to_owned());
                    }
                }
            }
        }
    }

    for header in extra_headers {
        while let Some(..) = headers.remove(&header) {}
    }

    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
    const HOP_BY_HOP_HEADERS: [&str; 9] = [
        "Keep-Alive",
        "Transfer-Encoding",
        "TE",
        "Connection",
        "Trailer",
        "Upgrade",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Proxy-Connection", // Not standard, but many implementations do send this header
    ];

    for header in &HOP_BY_HOP_HEADERS {
        while let Some(..) = headers.remove(*header) {}
    }
}

fn set_conn_keep_alive(version: Version, headers: &mut HeaderMap<HeaderValue>, keep_alive: bool) {
    match version {
        Version::HTTP_10 => {
            // HTTP/1.0 close connection by default
            if keep_alive {
                headers.insert("Connection", HeaderValue::from_static("keep-alive"));
            }
        }
        Version::HTTP_11 => {
            // HTTP/1.1 keep-alive connection by default
            if !keep_alive {
                headers.insert("Connection", HeaderValue::from_static("close"));
            }
        }
        _ => unimplemented!("HTTP Proxy only supports 1.0 and 1.1"),
    }
}

impl Connection for ProxyStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

type ShadowSocksHttpClient = Client<ShadowSocksConnector, Body>;
type DirectHttpClient = Client<DirectConnector, Body>;

async fn establish_connect_tunnel(upgraded: Upgraded, stream: ProxyStream, client_addr: SocketAddr, addr: Address) {
    use tokio::io::{copy, split};

    let (mut r, mut w) = split(upgraded);
    let (mut svr_r, mut svr_w) = stream.split();

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    debug!("CONNECT relay established {} <-> {}", client_addr, addr);

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!("CONNECT relay {} -> {} closed", client_addr, addr),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("CONNECT relay {} -> {} closed with error {}", client_addr, addr, err);
            } else {
                error!("CONNECT relay {} -> {} closed with error {}", client_addr, addr, err);
            }
        }
        Either::Right((Ok(..), _)) => trace!("CONNECT relay {} <- {} closed", client_addr, addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("CONNECT relay {} <- {} closed with error {}", client_addr, addr, err);
            } else {
                error!("CONNECT relay {} <- {} closed with error {}", client_addr, addr, err);
            }
        }
    }

    debug!("CONNECT relay {} <-> {} closed", client_addr, addr);
}

fn make_bad_request() -> io::Result<Response<Body>> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    Ok(resp)
}

fn get_addr_from_header(req: &mut Request<Body>) -> Result<Address, ()> {
    // Try to be compatible as a transparent HTTP proxy
    match req.headers().get("Host") {
        Some(hhost) => match hhost.to_str() {
            Ok(shost) => {
                match Authority::from_str(shost) {
                    Ok(authority) => match authority_addr(req.uri().scheme_str(), &authority) {
                        Some(host) => {
                            trace!("HTTP {} URI {} got host from header: {}", req.method(), req.uri(), host);

                            // Reassemble URI
                            let mut parts = req.uri().clone().into_parts();
                            if parts.scheme.is_none() {
                                // Use http as default.
                                parts.scheme = Some(Scheme::HTTP);
                            }
                            parts.authority = Some(authority);

                            // Replaces URI
                            *req.uri_mut() = Uri::from_parts(parts).expect("Reassemble URI failed");

                            debug!("reassembled URI from \"Host\", {}", req.uri());

                            Ok(host)
                        }
                        None => {
                            error!(
                                "HTTP {} URI {} \"Host\" header invalid, value: {}",
                                req.method(),
                                req.uri(),
                                shost
                            );

                            Err(())
                        }
                    },
                    Err(..) => {
                        error!(
                            "HTTP {} URI {} \"Host\" header is not an Authority, value: {:?}",
                            req.method(),
                            req.uri(),
                            hhost
                        );

                        Err(())
                    }
                }
            }
            Err(..) => {
                error!(
                    "HTTP {} URI {} \"Host\" header invalid encoding, value: {:?}",
                    req.method(),
                    req.uri(),
                    hhost
                );

                Err(())
            }
        },
        None => {
            error!(
                "HTTP {} URI doesn't have valid host and missing the \"Host\" header, URI: {}",
                req.method(),
                req.uri()
            );

            Err(())
        }
    }
}

async fn server_dispatch(
    mut req: Request<Body>,
    svr_score: SharedServerStatistic<ServerScore>,
    client_addr: SocketAddr,
    bypass_client: DirectHttpClient,
) -> io::Result<Response<Body>> {
    let context = svr_score.context();

    // Parse URI
    //
    // Proxy request URI must contains a host
    let host = match host_addr(req.uri()) {
        None => {
            if req.uri().authority().is_some() {
                // URI has authority but invalid
                error!("HTTP {} URI {} doesn't have a valid host", req.method(), req.uri());
                return make_bad_request();
            } else {
                trace!("HTTP {} URI {} doesn't have a valid host", req.method(), req.uri());
            }

            match get_addr_from_header(&mut req) {
                Ok(h) => h,
                Err(()) => return make_bad_request(),
            }
        }
        Some(h) => h,
    };

    let svr_cfg = svr_score.server_config();

    if Method::CONNECT == req.method() {
        // Establish a TCP tunnel
        // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

        debug!("HTTP CONNECT {}", host);

        // Connect to Shadowsocks' remote
        //
        // FIXME: What STATUS should I return for connection error?
        let stream = match ProxyStream::connect(svr_score.clone_context(), svr_cfg, &host).await {
            Ok(s) => s,
            Err(err) => {
                if err.is_proxied() {
                    // Report failure to global statistic
                    svr_score.report_failure().await;
                }
                return Err(err.into_inner());
            }
        };

        debug!("CONNECT relay connected {} <-> {}", client_addr, host);

        // Upgrade to a TCP tunnel
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        tokio::spawn(async move {
            match req.into_body().on_upgrade().await {
                Ok(upgraded) => {
                    trace!("CONNECT tunnel upgrade success, {} <-> {}", client_addr, host);

                    establish_connect_tunnel(upgraded, stream, client_addr, host).await
                }
                Err(e) => {
                    error!(
                        "failed to upgrade TCP tunnel {} <-> {}, error: {}",
                        client_addr, host, e
                    );
                }
            }
        });

        // Connection established
        let resp = Response::builder().body(Body::empty()).unwrap();

        Ok(resp)
    } else {
        let method = req.method().clone();

        debug!("HTTP {} {}", method, host);

        // Check if client wants us to keep long connection
        let conn_keep_alive = check_keep_alive(req.version(), req.headers(), true);

        // Remove non-forwardable headers
        clear_hop_headers(req.headers_mut());

        // Set keep-alive for connection with remote
        set_conn_keep_alive(req.version(), req.headers_mut(), conn_keep_alive);

        let mut res = if context.check_target_bypassed(&host).await {
            // Keep connections in a global client instance
            match bypass_client.request(req).await {
                Ok(res) => res,
                Err(err) => {
                    error!(
                        "HTTP {} {} <-> {} relay failed, error: {}",
                        method, client_addr, host, err
                    );

                    let mut resp = Response::new(Body::from(format!("relay failed to {}", host)));
                    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                    return Ok(resp);
                }
            }
        } else {
            // Keep connections for clients in ServerScore::client
            //
            // client instance is kept for Keep-Alive connections
            let client = &svr_score.server().proxy_client;

            match client.request(req).await {
                Ok(res) => res,
                Err(err) => {
                    error!(
                        "HTTP {} {} <-> {} relay failed, error: {}",
                        method, client_addr, host, err
                    );

                    let mut resp = Response::new(Body::from(format!("relay failed to {}", host)));
                    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

                    return Ok(resp);
                }
            }
        };

        let res_keep_alive = conn_keep_alive && check_keep_alive(res.version(), res.headers(), false);

        // Clear unforwardable headers
        clear_hop_headers(res.headers_mut());

        // Set Connection header
        set_conn_keep_alive(res.version(), res.headers_mut(), res_keep_alive);

        debug!("HTTP {} relay {} <-> {} finished", method, client_addr, host,);

        Ok(res)
    }
}

struct ServerScore {
    proxy_client: ShadowSocksHttpClient,
}

impl ServerScore {
    fn new(context: SharedContext, server_idx: usize, data: SharedServerStatisticData) -> ServerScore {
        ServerScore {
            // Create HTTP clients for each remote servers
            // It may reuse keep-alive connections
            proxy_client: Client::builder().build::<_, Body>(ShadowSocksConnector::new(context, server_idx, data)),
        }
    }
}

impl ServerData for ServerScore {
    fn create_server(context: &SharedContext, server_idx: usize, data: &SharedServerStatisticData) -> ServerScore {
        ServerScore::new(context.clone(), server_idx, data.clone())
    }
}

/// Starts a TCP local server with HTTP proxy protocol
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local.as_ref().expect("local config");
    let bind_addr = local_addr.bind_addr(&*context).await?;

    let bypass_client = Client::builder().build::<_, Body>(DirectConnector::new(context.clone()));
    let servers: PingBalancer<ServerScore> = PingBalancer::new(context, ServerType::Tcp).await;

    let make_service = make_service_fn(|socket: &AddrStream| {
        let client_addr = socket.remote_addr();
        let svr_score = servers.pick_server();
        let bypass_client = bypass_client.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                server_dispatch(req, svr_score.clone(), client_addr, bypass_client.clone())
            }))
        }
    });

    let server = Server::bind(&bind_addr).http1_only(true).serve(make_service);
    info!("shadowsocks HTTP listening on {}", server.local_addr());

    if let Err(err) = server.await {
        use std::io::Error;

        error!("hyper server exited with error: {}", err);
        return Err(Error::new(ErrorKind::Other, err));
    }

    Ok(())
}
