//! Shadowsocks HTTP Proxy server dispatcher

use std::{net::SocketAddr, str::FromStr, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri, Version, body,
    header::{self, HeaderValue},
    http::uri::{Authority, Scheme},
};
use log::{debug, error, trace};
use shadowsocks::relay::Address;

use crate::local::{
    context::ServiceContext,
    http::{http_client::HttpClientError, tokio_rt::TokioIo},
    loadbalancing::PingBalancer,
    net::AutoProxyIo,
    utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
};

use super::{
    http_client::HttpClient,
    utils::{authority_addr, check_keep_alive, connect_host, host_addr},
};

pub struct HttpService {
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    http_client: HttpClient<body::Incoming>,
    balancer: PingBalancer,
}

impl HttpService {
    pub fn new(
        context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        http_client: HttpClient<body::Incoming>,
        balancer: PingBalancer,
    ) -> Self {
        Self {
            context,
            peer_addr,
            http_client,
            balancer,
        }
    }

    pub async fn serve_connection(
        self,
        mut req: Request<body::Incoming>,
    ) -> hyper::Result<Response<BoxBody<Bytes, hyper::Error>>> {
        trace!("request {} {:?}", self.peer_addr, req);

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

        if req.method() == Method::CONNECT {
            // Establish a TCP tunnel
            // https://tools.ietf.org/html/draft-luotonen-web-proxy-tunneling-01

            debug!("HTTP CONNECT {}", host);

            // Connect to Shadowsocks' remote
            //
            // FIXME: What STATUS should I return for connection error?
            let (mut stream, server_opt) = match connect_host(self.context, &host, Some(&self.balancer)).await {
                Ok(s) => s,
                Err(err) => {
                    error!("failed to CONNECT host: {}, error: {}", host, err);
                    return make_internal_server_error();
                }
            };

            debug!(
                "CONNECT relay connected {} <-> {} ({})",
                self.peer_addr,
                host,
                if stream.is_bypassed() { "bypassed" } else { "proxied" }
            );

            let client_addr = self.peer_addr;
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        trace!("CONNECT tunnel upgrade success, {} <-> {}", client_addr, host);

                        let mut upgraded_io = TokioIo::new(upgraded);

                        let _ = match server_opt {
                            Some(server) => {
                                establish_tcp_tunnel(
                                    server.server_config(),
                                    &mut upgraded_io,
                                    &mut stream,
                                    client_addr,
                                    &host,
                                )
                                .await
                            }
                            None => {
                                establish_tcp_tunnel_bypassed(&mut upgraded_io, &mut stream, client_addr, &host).await
                            }
                        };
                    }
                    Err(err) => {
                        error!("failed to upgrade CONNECT request, error: {}", err);
                    }
                }
            });

            return Ok(Response::new(empty_body()));
        }

        // Traditional HTTP Proxy request

        let method = req.method().clone();
        let version = req.version();
        debug!("HTTP {} {} {:?}", method, host, version);

        // Check if client wants us to keep long connection
        let conn_keep_alive = check_keep_alive(version, req.headers(), true);

        // Remove non-forwardable headers
        clear_hop_headers(req.headers_mut());

        // Set keep-alive for connection with remote
        set_conn_keep_alive(version, req.headers_mut(), conn_keep_alive);

        let mut res = match self
            .http_client
            .send_request(self.context, req, Some(&self.balancer))
            .await
        {
            Ok(resp) => resp,
            Err(HttpClientError::Hyper(e)) => return Err(e),
            Err(HttpClientError::Io(err)) => {
                error!("failed to make request to host: {}, error: {}", host, err);
                return make_internal_server_error();
            }
            Err(HttpClientError::Http(err)) => {
                error!("failed to make request to host: {}, error: {}", host, err);
                return make_bad_request();
            }
            Err(HttpClientError::InvalidHeaderValue(err)) => {
                error!("failed to make request to host: {}, error: {}", host, err);
                return make_bad_request();
            }
        };

        trace!("received {} <- {} {:?}", self.peer_addr, host, res);

        let res_keep_alive = conn_keep_alive && check_keep_alive(res.version(), res.headers(), false);

        // Clear unforwardable headers
        clear_hop_headers(res.headers_mut());

        if res.version() != version {
            // Reset version to matches req's version
            trace!("response version {:?} => {:?}", res.version(), version);
            *res.version_mut() = version;
        }

        // Set Connection header
        set_conn_keep_alive(res.version(), res.headers_mut(), res_keep_alive);

        trace!("response {} <- {} {:?}", self.peer_addr, host, res);

        debug!("HTTP {} relay {} <-> {} finished", method, self.peer_addr, host);

        Ok(res.map(|b| b.boxed()))
    }
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn make_bad_request() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty_body())
        .unwrap())
}

fn make_internal_server_error() -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(empty_body())
        .unwrap())
}

fn get_extra_headers(headers: header::GetAll<HeaderValue>) -> Vec<String> {
    let mut extra_headers = Vec::new();
    for connection in headers {
        if let Ok(conn) = connection.to_str() {
            // close is a command instead of a header
            if conn.eq_ignore_ascii_case("close") {
                continue;
            }
            for header in conn.split(',') {
                let header = header.trim();
                extra_headers.push(header.to_owned());
            }
        }
    }
    extra_headers
}

fn clear_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    // Clear headers indicated by Connection and Proxy-Connection
    let mut extra_headers = get_extra_headers(headers.get_all("Connection"));
    extra_headers.extend(get_extra_headers(headers.get_all("Proxy-Connection")));

    for header in extra_headers {
        while headers.remove(&header).is_some() {}
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
        while headers.remove(*header).is_some() {}
    }
}

fn set_conn_keep_alive(version: Version, headers: &mut HeaderMap<HeaderValue>, keep_alive: bool) {
    match version {
        Version::HTTP_09 | Version::HTTP_10 => {
            // HTTP/1.0 close connection by default
            if keep_alive {
                headers.insert("Connection", HeaderValue::from_static("keep-alive"));
            }
        }
        _ => {
            // HTTP/1.1, HTTP/2, HTTP/3 keep-alive connection by default
            if !keep_alive {
                headers.insert("Connection", HeaderValue::from_static("close"));
            }
        }
    }
}

fn get_addr_from_header(req: &mut Request<body::Incoming>) -> Result<Address, ()> {
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
