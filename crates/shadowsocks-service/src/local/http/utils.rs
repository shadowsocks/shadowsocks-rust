//! HTTP Utilities

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use hyper::{
    HeaderMap, Uri, Version,
    header::{self, HeaderValue},
    http::uri::Authority,
};
use log::error;
use shadowsocks::relay::socks5::Address;

use crate::local::{
    context::ServiceContext,
    loadbalancing::{PingBalancer, ServerIdent},
    net::AutoProxyClientStream,
};

pub fn authority_addr(scheme_str: Option<&str>, authority: &Authority) -> Option<Address> {
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

pub fn host_addr(uri: &Uri) -> Option<Address> {
    match uri.authority() {
        None => None,
        Some(authority) => authority_addr(uri.scheme_str(), authority),
    }
}

fn get_keep_alive_val(values: header::GetAll<HeaderValue>) -> Option<bool> {
    let mut conn_keep_alive = None;
    for value in values {
        if let Ok(value) = value.to_str() {
            if value.eq_ignore_ascii_case("close") {
                conn_keep_alive = Some(false);
            } else {
                for part in value.split(',') {
                    let part = part.trim();
                    if part.eq_ignore_ascii_case("keep-alive") {
                        conn_keep_alive = Some(true);
                        break;
                    }
                }
            }
        }
    }
    conn_keep_alive
}

pub fn check_keep_alive(version: Version, headers: &HeaderMap<HeaderValue>, check_proxy: bool) -> bool {
    // HTTP/1.1, HTTP/2, HTTP/3 keeps alive by default
    let mut conn_keep_alive = !matches!(version, Version::HTTP_09 | Version::HTTP_10);

    if check_proxy {
        // Modern browsers will send Proxy-Connection instead of Connection
        // for HTTP/1.0 proxies which blindly forward Connection to remote
        //
        // https://tools.ietf.org/html/rfc7230#appendix-A.1.2
        if let Some(b) = get_keep_alive_val(headers.get_all("Proxy-Connection")) {
            conn_keep_alive = b
        }
    }

    // Connection will replace Proxy-Connection
    //
    // But why client sent both Connection and Proxy-Connection? That's not standard!
    if let Some(b) = get_keep_alive_val(headers.get_all("Connection")) {
        conn_keep_alive = b
    }

    conn_keep_alive
}

pub async fn connect_host(
    context: Arc<ServiceContext>,
    host: &Address,
    balancer: Option<&PingBalancer>,
) -> io::Result<(AutoProxyClientStream, Option<Arc<ServerIdent>>)> {
    match balancer {
        None => match AutoProxyClientStream::connect_bypassed(context, host).await {
            Ok(s) => Ok((s, None)),
            Err(err) => {
                error!("failed to connect host {} bypassed, err: {}", host, err);
                Err(err)
            }
        },
        Some(balancer) if balancer.is_empty() => match AutoProxyClientStream::connect_bypassed(context, host).await {
            Ok(s) => Ok((s, None)),
            Err(err) => {
                error!("failed to connect host {} bypassed, err: {}", host, err);
                Err(err)
            }
        },
        Some(balancer) => {
            let server = balancer.best_tcp_server();

            match AutoProxyClientStream::connect_with_opts(context, server.as_ref(), host, server.connect_opts_ref())
                .await
            {
                Ok(s) => Ok((s, Some(server))),
                Err(err) => {
                    error!(
                        "failed to connect host {} proxied, svr_cfg: {}, error: {}",
                        host,
                        server.server_config().addr(),
                        err
                    );
                    Err(err)
                }
            }
        }
    }
}
