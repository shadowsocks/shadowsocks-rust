//! Outbound proxy chain support.
//!
//! Provides a unified [`OutboundProxyClient`] that connects through a chain
//! of intermediate proxies (SOCKS5 / HTTP / HTTPS / Shadowsocks) before reaching the
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

use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, Instant},
};

use shadowsocks::{
    config::ServerConfig,
    context::SharedContext,
    net::ConnectOpts,
    plugin::{Plugin, PluginMode},
    relay::socks5::Address,
};
use tokio::sync::Mutex;

use crate::config::{OutboundProxy, OutboundProxyProtocol, PlainProxy};

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
/// [`OutboundProxyClient::try_from_config`]; keeps the protocol-specific
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

    async fn wait_plugin_started(&self) -> io::Result<()> {
        match &self.kind {
            OutboundProxyKind::Ss {
                plugin: Some(plugin), ..
            } => plugin.wait_started().await,
            _ => Ok(()),
        }
    }
}

/// Keeps a first-hop SIP003 plugin alive for the lifetime of its outbound client.
pub struct PluginHandle {
    plugin: Plugin,
    readiness: Mutex<PluginReadiness>,
}

enum PluginReadiness {
    Pending,
    Started,
    Failed { retry_at: Instant, message: String },
}

impl PluginHandle {
    const START_TIMEOUT: Duration = Duration::from_secs(3);
    const RETRY_DELAY: Duration = Duration::from_secs(1);

    fn new(plugin: Plugin) -> Self {
        Self {
            plugin,
            readiness: Mutex::new(PluginReadiness::Pending),
        }
    }

    async fn wait_started(&self) -> io::Result<()> {
        // Serialize readiness probes so a busy client cannot start a new
        // three-second wait for every concurrent connection. A failure is
        // cached briefly, then retried so a slow plugin can still recover.
        let mut readiness = self.readiness.lock().await;
        match &*readiness {
            PluginReadiness::Started => return Ok(()),
            PluginReadiness::Failed { retry_at, message } if Instant::now() < *retry_at => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, message.clone()));
            }
            PluginReadiness::Pending | PluginReadiness::Failed { .. } => {}
        }

        if self.plugin.wait_started(Self::START_TIMEOUT).await {
            *readiness = PluginReadiness::Started;
            Ok(())
        } else {
            let message = format!(
                "outbound proxy plugin on {} did not start within {} seconds",
                self.plugin.local_addr(),
                Self::START_TIMEOUT.as_secs()
            );
            *readiness = PluginReadiness::Failed {
                retry_at: Instant::now() + Self::RETRY_DELAY,
                message: message.clone(),
            };
            Err(io::Error::new(io::ErrorKind::TimedOut, message))
        }
    }
}

impl fmt::Debug for PluginHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.readiness.try_lock().as_deref() {
            Ok(PluginReadiness::Pending) => "pending",
            Ok(PluginReadiness::Started) => "started",
            Ok(PluginReadiness::Failed { .. }) => "failed",
            Err(_) => "checking",
        };
        f.debug_struct("PluginHandle")
            .field("local_addr", &self.plugin.local_addr())
            .field("state", &state)
            .finish()
    }
}

/// Per-protocol settings for one [`OutboundProxyHop`].
#[derive(Clone)]
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
    /// Shadowsocks encrypted hop. The plugin is only supported on the first hop.
    Ss {
        svr_cfg: Arc<ServerConfig>,
        plugin: Option<Arc<PluginHandle>>,
    },
}

impl fmt::Debug for OutboundProxyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks5 { auth } => f.debug_struct("Socks5").field("auth", auth).finish(),
            Self::Http { auth } => f.debug_struct("Http").field("auth", auth).finish(),
            Self::Https { auth, sni } => f.debug_struct("Https").field("auth", auth).field("sni", sni).finish(),
            Self::Ss { svr_cfg, plugin } => f
                .debug_struct("Ss")
                .field("addr", &svr_cfg.addr())
                .field("method", &svr_cfg.method())
                .field("password", &"<redacted>")
                .field("plugin", plugin)
                .finish(),
        }
    }
}

/// Unified outbound proxy client.
///
/// Construct from configuration via [`Self::try_from_config`]. The instance
/// can be cached (e.g. inside `ServiceContext`) and reused across
/// connections.
#[derive(Debug, Clone)]
pub struct OutboundProxyClient {
    hops: Arc<[OutboundProxyHop]>,
}

impl OutboundProxyClient {
    /// Build a client from a (possibly empty) list of `OutboundProxy`
    /// configuration entries.
    pub fn try_from_config(proxies: &[OutboundProxy]) -> io::Result<Self> {
        Self::try_from_config_with_hop_offset(proxies, 0)
    }

    /// Build the trailing hops of an `sslocal` chain whose configured main
    /// Shadowsocks server is hop zero.
    ///
    /// SIP003 plugins are only usable on the physical first hop. Starting
    /// indices at one makes plugin-bearing entries in `outbound_proxy` fail
    /// during configuration instead of trying to start an unreachable local
    /// plugin for a later hop.
    pub fn try_from_config_after_main_server(proxies: &[OutboundProxy]) -> io::Result<Self> {
        Self::try_from_config_with_hop_offset(proxies, 1)
    }

    fn try_from_config_with_hop_offset(proxies: &[OutboundProxy], hop_offset: usize) -> io::Result<Self> {
        let hops = proxies
            .iter()
            .enumerate()
            .map(|(idx, proxy)| hop_from_config(idx + hop_offset, proxy))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { hops: hops.into() })
    }

    /// Whether a configuration can use the existing SOCKS5-only UDP relay path.
    pub fn config_supports_udp(proxies: &[OutboundProxy]) -> bool {
        !proxies.is_empty() && proxies.iter().all(OutboundProxy::supports_udp)
    }

    /// Whether a configuration contains a Shadowsocks outbound hop.
    pub fn config_contains_shadowsocks_hop(proxies: &[OutboundProxy]) -> bool {
        proxies.iter().any(|proxy| matches!(proxy, OutboundProxy::Ss(_)))
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

    /// Whether this chain contains a Shadowsocks outbound hop.
    pub fn contains_shadowsocks_hop(&self) -> bool {
        self.hops
            .iter()
            .any(|hop| matches!(hop.kind, OutboundProxyKind::Ss { .. }))
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

fn hop_from_config(idx: usize, proxy: &OutboundProxy) -> io::Result<OutboundProxyHop> {
    match proxy {
        OutboundProxy::Plain(proxy) => plain_hop(proxy),
        OutboundProxy::Ss(hop) => {
            let mut svr_cfg = hop.svr_cfg.clone();
            let plugin = match svr_cfg.plugin().cloned() {
                Some(plugin_cfg) => {
                    if idx != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "plugin on non-first ss outbound proxy hop requires rendezvous support",
                        ));
                    }

                    let plugin = Plugin::start(&plugin_cfg, svr_cfg.addr(), PluginMode::Client)?;
                    svr_cfg.set_plugin_addr(plugin.local_addr().into());
                    Some(Arc::new(PluginHandle::new(plugin)))
                }
                None => None,
            };

            Ok(OutboundProxyHop {
                addr: svr_cfg.tcp_external_addr().into(),
                kind: OutboundProxyKind::Ss {
                    svr_cfg: Arc::new(svr_cfg),
                    plugin,
                },
            })
        }
    }
}

fn plain_hop(proxy: &PlainProxy) -> io::Result<OutboundProxyHop> {
    let addr = match proxy.host.parse() {
        Ok(ip) => Address::SocketAddress(std::net::SocketAddr::new(ip, proxy.port)),
        Err(..) => Address::DomainNameAddress(proxy.host.clone(), proxy.port),
    };
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
        OutboundProxyProtocol::Ss => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plain outbound proxy cannot use the ss scheme",
            ));
        }
    };

    Ok(OutboundProxyHop { addr, kind })
}

fn http_auth_from_config(proxy: &PlainProxy) -> HttpProxyAuth {
    match proxy.auth.as_ref() {
        Some(a) => HttpProxyAuth::basic(a.username.clone(), a.password.clone()),
        None => HttpProxyAuth::None,
    }
}
