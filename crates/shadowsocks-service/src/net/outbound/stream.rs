//! Type-erased outbound proxy stream.
//!
//! Replaces the previous `Box<dyn ProxyStream>` based implementations with a
//! closed-set enum. All variants are statically dispatched (`pin_project`
//! forwards `poll_*` directly). The `Https` variant boxes its inner
//! [`OutboundProxyStream`] purely to break recursive type instantiation —
//! that boxing is **not** dynamic dispatch.

use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    task::{self, Poll},
};

use pin_project::pin_project;
use shadowsocks::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "local-http")]
use super::http_connect::HttpConnectTunnel;
#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
use super::tls::OutboundTlsStream;

/// Outbound proxy stream returned by [`super::OutboundProxyClient::connect_tcp`].
///
/// This is the unified return type used everywhere a proxy chain is
/// established. Implements [`AsyncRead`] / [`AsyncWrite`].
///
/// Each variant carries the local address that the very first TCP hop was
/// dialled from, so [`Self::local_addr`] is always available regardless of
/// any TLS or HTTP CONNECT upgrades layered on top.
pub struct OutboundProxyStream {
    local_addr: SocketAddr,
    inner: OutboundProxyStreamInner,
}

#[allow(clippy::large_enum_variant)]
#[pin_project(project = OutboundProxyStreamInnerProj)]
enum OutboundProxyStreamInner {
    /// Plain TCP. Either no proxy chain is configured (used internally by
    /// the chain builder) or the SOCKS5 hop has just completed its
    /// handshake on top of a TCP connection — SOCKS5 negotiation does not
    /// transform the wire layer, so the variant stays `Bypassed`.
    Bypassed(#[pin] TcpStream),

    /// TLS layered on top of an inner [`OutboundProxyStream`]. Used by
    /// HTTPS proxy hops.
    #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
    Https(#[pin] OutboundTlsStream),

    /// Tunnel obtained from a successful HTTP CONNECT upgrade.
    #[cfg(feature = "local-http")]
    Http(#[pin] HttpConnectTunnel),
}

impl OutboundProxyStream {
    /// Construct from a freshly dialled [`TcpStream`].
    pub fn from_tcp(stream: TcpStream) -> io::Result<Self> {
        let local_addr = stream.local_addr()?;
        Ok(Self {
            local_addr,
            inner: OutboundProxyStreamInner::Bypassed(stream),
        })
    }

    /// Construct from a freshly dialled [`TcpStream`] with a precomputed
    /// `local_addr` (avoids a syscall when the address is already known).
    pub fn from_tcp_with_local_addr(stream: TcpStream, local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            inner: OutboundProxyStreamInner::Bypassed(stream),
        }
    }

    /// Local socket address of the first TCP hop. Always available, even
    /// after TLS / HTTP CONNECT layers have been applied.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// Try to recover the underlying [`TcpStream`].
    ///
    /// Succeeds only if the stream is still in the unwrapped TCP state
    /// (i.e. no TLS or HTTP CONNECT layer has been applied). The UDP
    /// outbound path uses this to obtain a keep-alive connection that is
    /// `Sync`-friendly (`OutboundProxyStream` itself is intentionally not
    /// `Sync` because the HTTP CONNECT variant wraps a
    /// `hyper::upgrade::Upgraded` which is not).
    #[allow(clippy::result_large_err)]
    pub fn try_into_tcp(self) -> Result<TcpStream, Self> {
        match self.inner {
            OutboundProxyStreamInner::Bypassed(s) => Ok(s),
            other => Err(Self {
                local_addr: self.local_addr,
                inner: other,
            }),
        }
    }

    /// Wrap as a TLS-protected stream (used by the chain builder when the
    /// next hop is HTTPS). `local_addr` is the address recorded for the
    /// very first TCP hop and is preserved unchanged.
    #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
    pub(super) fn from_tls(local_addr: SocketAddr, tls: OutboundTlsStream) -> Self {
        Self {
            local_addr,
            inner: OutboundProxyStreamInner::Https(tls),
        }
    }

    /// Wrap as an upgraded HTTP CONNECT tunnel.
    #[cfg(feature = "local-http")]
    pub(super) fn from_http(local_addr: SocketAddr, tunnel: HttpConnectTunnel) -> Self {
        Self {
            local_addr,
            inner: OutboundProxyStreamInner::Http(tunnel),
        }
    }

    /// Project the pinned `inner` enum.
    fn project_inner(self: Pin<&mut Self>) -> OutboundProxyStreamInnerProj<'_> {
        // SAFETY: `local_addr` is `Copy` and not pin-projected; only `inner`
        // requires pin projection. `OutboundProxyStream` itself is `Unpin`
        // (declared explicitly below) — none of the inner variants are
        // self-referential, and the unsafe projection here is only used
        // internally.
        unsafe {
            let this = self.get_unchecked_mut();
            Pin::new_unchecked(&mut this.inner).project()
        }
    }
}

// Safe: `inner` is only ever pin-projected through the controlled
// [`Self::project_inner`] helper. Marking the wrapper `Unpin` lets
// `Box<OutboundProxyStream>` participate as the inner I/O for TLS streams
// (their `AsyncRead`/`AsyncWrite` impls require `Unpin`).
impl Unpin for OutboundProxyStream {}

impl AsyncRead for OutboundProxyStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project_inner() {
            OutboundProxyStreamInnerProj::Bypassed(s) => s.poll_read(cx, buf),
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            OutboundProxyStreamInnerProj::Https(s) => s.poll_read(cx, buf),
            #[cfg(feature = "local-http")]
            OutboundProxyStreamInnerProj::Http(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundProxyStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project_inner() {
            OutboundProxyStreamInnerProj::Bypassed(s) => s.poll_write(cx, buf),
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            OutboundProxyStreamInnerProj::Https(s) => s.poll_write(cx, buf),
            #[cfg(feature = "local-http")]
            OutboundProxyStreamInnerProj::Http(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project_inner() {
            OutboundProxyStreamInnerProj::Bypassed(s) => s.poll_flush(cx),
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            OutboundProxyStreamInnerProj::Https(s) => s.poll_flush(cx),
            #[cfg(feature = "local-http")]
            OutboundProxyStreamInnerProj::Http(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project_inner() {
            OutboundProxyStreamInnerProj::Bypassed(s) => s.poll_shutdown(cx),
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            OutboundProxyStreamInnerProj::Https(s) => s.poll_shutdown(cx),
            #[cfg(feature = "local-http")]
            OutboundProxyStreamInnerProj::Http(s) => s.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project_inner() {
            OutboundProxyStreamInnerProj::Bypassed(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            OutboundProxyStreamInnerProj::Https(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "local-http")]
            OutboundProxyStreamInnerProj::Http(s) => s.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            OutboundProxyStreamInner::Bypassed(s) => s.is_write_vectored(),
            // TLS / hyper upgraded streams don't expose vectored writes meaningfully.
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            OutboundProxyStreamInner::Https(_) => false,
            #[cfg(feature = "local-http")]
            OutboundProxyStreamInner::Http(_) => false,
        }
    }
}

// `tls.rs` boxes `OutboundProxyStream` directly inside its TLS wrapper.
// `Box::new(stream)` is used directly there; no helper is required here.
