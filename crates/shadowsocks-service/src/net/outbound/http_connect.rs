//! HTTP CONNECT outbound proxy client built on top of `hyper`.
//!
//! Replaces the previous hand-rolled status-line parser. By delegating to
//! `hyper::client::conn::http1` we get correct handling of:
//!
//! * Multiple-segment HTTP responses (the previous implementation could
//!   silently drop bytes that arrived in the same `read()` as the response
//!   header end marker).
//! * `100 Continue` interim responses.
//! * Header folding, status reasons with arbitrary spacing, etc.
//! * Connection upgrade semantics (`hyper::upgrade::on`).
//!
//! Only available when the `local-http` feature is enabled.

use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use http::{HeaderValue, Method as HttpMethod, Request, Uri, header::HOST};
use http_body_util::Empty;
use hyper::{
    body::{Bytes, Incoming},
    client::conn::http1,
    upgrade::Upgraded,
};
use log::{error, trace};
use pin_project::pin_project;
use shadowsocks::relay::socks5::Address;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::local::http::tokio_rt::TokioIo;

use super::auth::HttpProxyAuth;

/// Establish HTTP CONNECT tunnels.
pub struct HttpConnectClient;

impl HttpConnectClient {
    /// Negotiate `CONNECT target HTTP/1.1` over `stream` and return the
    /// upgraded byte tunnel.
    ///
    /// `stream` must be a fully-established byte stream to the HTTP proxy
    /// server (raw TCP, or TLS-wrapped for HTTPS proxies).
    pub async fn establish<S>(
        stream: S,
        target: &Address,
        auth: &HttpProxyAuth,
    ) -> io::Result<HttpConnectTunnel>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let authority = address_to_authority(target);

        let uri: Uri = authority
            .parse()
            .map_err(|err| io::Error::other(format!("invalid CONNECT authority {authority}: {err}")))?;

        let mut req_builder = Request::builder()
            .method(HttpMethod::CONNECT)
            .uri(uri)
            .header(HOST, &authority);

        match auth {
            HttpProxyAuth::None => {}
            HttpProxyAuth::Basic { username, password } => {
                let encoded = BASE64_STANDARD.encode(format!("{username}:{password}"));
                let header = HeaderValue::from_str(&format!("Basic {encoded}"))
                    .map_err(|err| io::Error::other(format!("invalid proxy basic auth: {err}")))?;
                req_builder = req_builder.header("Proxy-Authorization", header);
            }
        }

        let req = req_builder
            .body(Empty::<Bytes>::new())
            .map_err(|err| io::Error::other(format!("failed to build CONNECT request: {err}")))?;

        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|err| io::Error::other(format!("HTTP CONNECT handshake failed: {err}")))?;

        // Drive the connection in the background. `with_upgrades()` is
        // required so the connection task hands off the underlying byte
        // stream once the CONNECT response is received.
        tokio::spawn(async move {
            if let Err(err) = connection.with_upgrades().await {
                trace!("HTTP CONNECT connection task ended: {err}");
            }
        });

        trace!("HTTP CONNECT request to {authority}");
        let response = sender
            .send_request(req)
            .await
            .map_err(|err| io::Error::other(format!("HTTP CONNECT request failed: {err}")))?;

        let status = response.status();
        if !status.is_success() {
            error!("HTTP CONNECT to {authority} rejected with status {status}");
            return Err(io::Error::other(format!(
                "HTTP CONNECT proxy rejected tunnel with status {status}"
            )));
        }

        let upgraded = upgrade(response).await?;
        Ok(HttpConnectTunnel {
            inner: TokioIo::new(upgraded),
        })
    }
}

async fn upgrade(response: http::Response<Incoming>) -> io::Result<Upgraded> {
    hyper::upgrade::on(response)
        .await
        .map_err(|err| io::Error::other(format!("HTTP CONNECT upgrade failed: {err}")))
}

fn address_to_authority(addr: &Address) -> String {
    match addr {
        Address::SocketAddress(sa) if sa.is_ipv6() => format!("[{}]:{}", sa.ip(), sa.port()),
        Address::SocketAddress(sa) => sa.to_string(),
        Address::DomainNameAddress(host, port) => format!("{host}:{port}"),
    }
}

/// Established HTTP CONNECT tunnel. Implements [`AsyncRead`] / [`AsyncWrite`]
/// transparently, the same way a raw TCP stream would.
#[pin_project]
pub struct HttpConnectTunnel {
    #[pin]
    inner: TokioIo<Upgraded>,
}

impl AsyncRead for HttpConnectTunnel {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpConnectTunnel {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
