//! Outbound proxy chain support.
//!
//! Provides a unified [`OutboundProxyClient`] that connects through a chain
//! of intermediate proxies (SOCKS5 / HTTP / HTTPS) before reaching the
//! actual target. The previous implementation lived in two parallel files
//! (`net::outbound_proxy` for the server, `local::net::tcp::outbound_proxy`
//! for the local side) and leaked protocol-specific types
//! (`Socks5TcpClient::from_stream`, `OutboundProxyStream` based on
//! `Box<dyn>`). This module replaces both.
//!
//! # Architecture
//!
//! * [`auth`] — `Socks5Auth` / `HttpProxyAuth`, the per-protocol
//!   authentication enums (replaces the legacy
//!   `Option<(&[u8], &[u8])>` parameters).
//! * [`socks5`] — Pure SOCKS5 client (TCP/UDP), plus the chain-friendly
//!   [`socks5::Socks5Negotiator`] that operates on a borrowed byte stream.
//! * [`http_connect`] — HTTP CONNECT client built on top of `hyper`.
//! * [`tls`] — Shared TLS transport for HTTPS proxy hops.
//! * [`stream`] — [`OutboundProxyStream`], the unified statically-dispatched
//!   tunnel returned by the chain builder.
//! * [`chain`] — The chain construction algorithm itself.

use std::{io, sync::Arc};

use shadowsocks::{
    context::SharedContext,
    net::ConnectOpts,
    relay::socks5::Address,
};

use crate::config::{OutboundProxy, OutboundProxyProtocol};

pub mod auth;
pub mod chain;
#[cfg(feature = "local-http")]
pub mod http_connect;
pub mod socks5;
pub mod stream;
pub mod tls;
pub mod udp;

pub use auth::{HttpProxyAuth, Socks5Auth};
pub use socks5::Socks5Negotiator;
pub use stream::OutboundProxyStream;
pub use udp::OutboundProxyDatagram;

#[cfg(feature = "local-http")]
pub use http_connect::{HttpConnectClient, HttpConnectTunnel};

/// Trait used by [`OutboundProxyClient`] to dial the first hop of the
/// chain. Each caller (server / local) injects its own implementation so
/// that the existing `ConnectOpts` / bypass routing rules continue to
/// apply.
#[trait_variant::make(Send)]
pub trait TcpDialer {
    /// Dial a TCP connection to `addr`.
    async fn dial(&self, addr: &Address) -> io::Result<shadowsocks::net::TcpStream>;
}

/// One protocol-friendly hop. Built from [`OutboundProxy`] via
/// [`OutboundProxyClient::from_config`]; keeps the protocol-specific
/// authentication info pre-converted so the data path doesn't have to
/// touch [`crate::config`] at all.
#[derive(Debug, Clone)]
pub struct OutboundProxyHop {
    /// Address of the proxy server itself (`proxy.host:proxy.port`).
    pub addr: Address,
    /// Per-protocol configuration.
    pub kind: OutboundProxyKind,
}

impl OutboundProxyHop {
    fn is_https(&self) -> bool {
        matches!(self.kind, OutboundProxyKind::Https { .. })
    }

    #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
    fn tls_sni(&self) -> &str {
        match &self.kind {
            OutboundProxyKind::Https { sni, .. } => sni,
            _ => unreachable!("tls_sni called on non-HTTPS hop"),
        }
    }

    #[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
    fn tls_sni(&self) -> &str {
        ""
    }

    fn supports_udp(&self) -> bool {
        matches!(self.kind, OutboundProxyKind::Socks5 { .. })
    }
}

/// Per-protocol settings for one [`OutboundProxyHop`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum OutboundProxyKind {
    /// SOCKS5 proxy.
    Socks5 { auth: Socks5Auth },
    /// HTTP proxy (CONNECT method).
    Http { auth: HttpProxyAuth },
    /// HTTPS proxy (CONNECT method, TLS-wrapped wire).
    Https {
        auth: HttpProxyAuth,
        /// Server name to use for TLS SNI.
        sni: String,
    },
}

/// Unified outbound proxy client.
///
/// Construct from configuration via [`Self::from_config`]. The instance
/// can be cached (e.g. inside `ServiceContext`) and reused across
/// connections.
#[derive(Debug, Clone)]
pub struct OutboundProxyClient {
    hops: Arc<[OutboundProxyHop]>,
}

impl OutboundProxyClient {
    /// Build a client from a (possibly empty) list of `OutboundProxy`
    /// configuration entries.
    pub fn from_config(proxies: &[OutboundProxy]) -> Self {
        let hops: Vec<OutboundProxyHop> = proxies.iter().map(hop_from_config).collect();
        Self { hops: hops.into() }
    }

    /// Underlying hops.
    pub fn hops(&self) -> &[OutboundProxyHop] {
        &self.hops
    }

    /// Number of hops.
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Whether **every** hop in the chain supports relaying UDP datagrams.
    /// Currently this is equivalent to "every hop is SOCKS5".
    pub fn supports_udp(&self) -> bool {
        !self.hops.is_empty() && self.hops.iter().all(OutboundProxyHop::supports_udp)
    }

    /// Establish a multi-hop UDP relay through the chain.
    ///
    /// Requires every hop to be SOCKS5 (see [`Self::supports_udp`]).
    /// `target` is the inner-most destination address baked into every
    /// outgoing datagram's SOCKS5 UDP header (typically the ss-server's
    /// UDP external address).
    pub async fn associate_udp<D>(
        &self,
        context: &SharedContext,
        dialer: &D,
        connect_opts: &ConnectOpts,
        target: Address,
    ) -> io::Result<OutboundProxyDatagram>
    where
        D: TcpDialer + Sync,
    {
        OutboundProxyDatagram::associate(self, context, dialer, connect_opts, target).await
    }
}

fn hop_from_config(proxy: &OutboundProxy) -> OutboundProxyHop {
    let addr = proxy.address();
    let kind = match proxy.protocol {
        OutboundProxyProtocol::Socks5 => {
            let auth = match proxy.auth.as_ref() {
                Some(a) => Socks5Auth::username_password(a.username.as_bytes(), a.password.as_bytes()),
                None => Socks5Auth::None,
            };
            OutboundProxyKind::Socks5 { auth }
        }
        OutboundProxyProtocol::Http => OutboundProxyKind::Http {
            auth: http_auth_from_config(proxy),
        },
        OutboundProxyProtocol::Https => OutboundProxyKind::Https {
            auth: http_auth_from_config(proxy),
            sni: proxy.host.clone(),
        },
    };

    OutboundProxyHop { addr, kind }
}

fn http_auth_from_config(proxy: &OutboundProxy) -> HttpProxyAuth {
    match proxy.auth.as_ref() {
        Some(a) => HttpProxyAuth::basic(a.username.clone(), a.password.clone()),
        None => HttpProxyAuth::None,
    }
}
