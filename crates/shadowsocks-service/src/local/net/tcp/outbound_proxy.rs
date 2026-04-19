//! Outbound proxy chain connection for the local side
//!
//! Connects to the shadowsocks server through a proxy chain, using the shared
//! HTTP/HTTPS transport helper for TLS support.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use shadowsocks::{net::ConnectOpts, relay::socks5::Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    config::{OutboundProxy, OutboundProxyProtocol},
    local::context::ServiceContext,
    net::{http_stream::ProxyHttpStream, outbound_proxy::connect_via_proxy},
};

use super::auto_proxy_stream::AutoProxyClientStream;

trait BoxableStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> BoxableStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Type-erased stream for outbound proxy chain connections.
///
/// Hides the concrete stream type (direct, TLS-wrapped, etc.) behind a single
/// public type so that `AutoProxyClientStream::ProxiedViaChain` can hold it without
/// leaking private trait bounds.
pub struct OutboundProxyStream {
    stream: Box<dyn BoxableStream + 'static>,
    local_addr: SocketAddr,
}

impl OutboundProxyStream {
    fn new<S: BoxableStream + 'static>(stream: S, local_addr: SocketAddr) -> Self {
        Self {
            stream: Box::new(stream),
            local_addr,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

impl Unpin for OutboundProxyStream {}

impl AsyncRead for OutboundProxyStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for OutboundProxyStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

/// Connect to `target` through the outbound proxy chain.
///
/// The first connection is established via `AutoProxyClientStream::connect_bypassed()`,
/// which uses the shadowsocks infrastructure (DNS, connect opts, etc.).
/// HTTPS proxies use the shared `ProxyHttpStream::connect_https()` helper,
/// the same transport used by the local HTTP client for TLS connections.
pub async fn connect_outbound_proxy_chain(
    context: Arc<ServiceContext>,
    target: Address,
    proxies: &[OutboundProxy],
    connect_opts: &ConnectOpts,
) -> io::Result<OutboundProxyStream> {
    let Some(first_proxy) = proxies.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty outbound proxy chain",
        ));
    };

    let first_addr = first_proxy.address();

    // Use AutoProxyClientStream for the first connection — this reuses the
    // shadowsocks DNS resolver, connect options, and bind interface settings.
    let initial = AutoProxyClientStream::connect_bypassed_with_opts(context.clone(), &first_addr, connect_opts).await?;
    let local_addr = initial.local_addr()?;

    // For the first proxy: if it's HTTPS, TLS-wrap with the shared helper that is
    // also used by the local HTTP client. Otherwise box directly.
    let mut stream: OutboundProxyStream = if first_proxy.protocol == OutboundProxyProtocol::Https {
        #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
        {
            let tls = ProxyHttpStream::connect_https(initial, &first_proxy.host).await?;
            OutboundProxyStream::new(tls, local_addr)
        }

        #[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HTTPS outbound proxy requires either local-http-native-tls or local-http-rustls feature",
            ));
        }
    } else {
        OutboundProxyStream::new(initial, local_addr)
    };

    // Process each proxy hop in order.
    for (idx, proxy) in proxies.iter().enumerate() {
        if idx > 0 && proxy.protocol == OutboundProxyProtocol::Https {
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            {
                let local_addr = stream.local_addr()?;
                let tls = ProxyHttpStream::connect_https(stream, &proxy.host).await?;
                stream = OutboundProxyStream::new(tls, local_addr);
            }

            #[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
            {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "HTTPS outbound proxy requires either local-http-native-tls or local-http-rustls feature",
                ));
            }
        }

        let next_target = proxies
            .get(idx + 1)
            .map(OutboundProxy::address)
            .unwrap_or_else(|| target.clone());

        connect_via_proxy(&mut stream, proxy, &next_target).await?;
    }

    Ok(stream)
}
