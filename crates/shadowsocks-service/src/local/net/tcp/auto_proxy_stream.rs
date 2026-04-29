//! A `ProxyStream` that bypasses or proxies data through proxy server automatically

use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use log::trace;
use pin_project::pin_project;
use shadowsocks::{
    net::{ConnectOpts, TcpStream},
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    local::{context::ServiceContext, loadbalancing::ServerIdent},
    net::{MonProxyStream, OutboundProxyStream, TcpDialer},
};

use super::auto_proxy_io::AutoProxyIo;

/// Outbound transport used by [`AutoProxyClientStream`]: either a direct
/// TCP connection or a tunnel through the configured outbound proxy chain.
#[allow(clippy::large_enum_variant)]
#[pin_project(project = OutboundTransportProj)]
pub enum OutboundTransport {
    /// Direct TCP, no outbound chain configured.
    Direct(#[pin] TcpStream),
    /// Tunnel produced by `OutboundProxyClient::connect_tcp`.
    Chained(#[pin] OutboundProxyStream),
}

impl OutboundTransport {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Direct(s) => s.local_addr(),
            Self::Chained(s) => s.local_addr(),
        }
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            Self::Direct(s) => s.set_nodelay(nodelay),
            // For tunnels we can only forward the request to the underlying
            // TCP socket if it is exposed; the unified enum has no such
            // accessor today, so the call is a no-op.
            Self::Chained(_) => Ok(()),
        }
    }
}

impl AsyncRead for OutboundTransport {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_read(cx, buf),
            OutboundTransportProj::Chained(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundTransport {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_write(cx, buf),
            OutboundTransportProj::Chained(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_flush(cx),
            OutboundTransportProj::Chained(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_shutdown(cx),
            OutboundTransportProj::Chained(s) => s.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            OutboundTransportProj::Direct(s) => s.poll_write_vectored(cx, bufs),
            OutboundTransportProj::Chained(s) => s.poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Direct(s) => s.is_write_vectored(),
            Self::Chained(s) => s.is_write_vectored(),
        }
    }
}

/// `TcpDialer` adapter that dials directly via the shadowsocks
/// infrastructure (DNS resolver, connect options).
struct DirectTcpDialer<'a> {
    context: &'a ServiceContext,
    opts: &'a ConnectOpts,
}

impl<'a> TcpDialer for DirectTcpDialer<'a> {
    async fn dial(&self, addr: &Address) -> io::Result<TcpStream> {
        TcpStream::connect_remote_with_opts(self.context.context_ref(), addr, self.opts).await
    }
}

/// Unified stream for bypassed and proxied connections
#[allow(clippy::large_enum_variant)]
#[pin_project(project = AutoProxyClientStreamProj)]
pub enum AutoProxyClientStream {
    /// Tunnel through the shadowsocks server (optionally over the outbound
    /// proxy chain).
    Proxied(#[pin] ProxyClientStream<MonProxyStream<OutboundTransport>>),
    /// Direct TCP, bypassing the shadowsocks server.
    Bypassed(#[pin] TcpStream),
}

impl AutoProxyClientStream {
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect<A>(context: Arc<ServiceContext>, server: &ServerIdent, addr: A) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        Self::connect_with_opts(context.clone(), server, addr, context.connect_opts_ref()).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        if context.check_target_bypassed(&addr).await {
            trace!("Bypassing target address {addr}");
            Self::connect_bypassed_with_opts_inner(context, addr, opts).await
        } else {
            trace!("Proxying target address {addr}");
            Self::connect_proxied_with_opts_inner(context, server, addr, opts).await
        }
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed<A>(context: Arc<ServiceContext>, addr: A) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        Self::connect_bypassed_with_opts(context.clone(), addr, context.connect_opts_ref()).await
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed_with_opts<A>(
        context: Arc<ServiceContext>,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        Self::connect_bypassed_with_opts_inner(context, addr, connect_opts).await
    }

    async fn connect_bypassed_with_opts_inner<A>(
        context: Arc<ServiceContext>,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        let addr = addr.into();
        let stream = TcpStream::connect_remote_with_opts(context.context_ref(), &addr, connect_opts).await?;
        Ok(Self::Bypassed(stream))
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied<A>(context: Arc<ServiceContext>, server: &ServerIdent, addr: A) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        Self::connect_proxied_with_opts(context.clone(), server, addr, context.connect_opts_ref()).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        Self::connect_proxied_with_opts_inner(context, server, addr, connect_opts).await
    }

    async fn connect_proxied_with_opts_inner<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Self>
    where
        A: Into<Address>,
    {
        let flow_stat = context.flow_stat();
        let target_addr: Address = addr.into();
        let ss_addr: Address = server.server_config().tcp_external_addr().into();

        let dial_result = match context.outbound_client() {
            None => TcpStream::connect_remote_with_opts(context.context_ref(), &ss_addr, connect_opts)
                .await
                .map(OutboundTransport::Direct),
            Some(client) => {
                let dialer = DirectTcpDialer {
                    context: context.as_ref(),
                    opts: connect_opts,
                };
                client
                    .connect_tcp(&dialer, &ss_addr)
                    .await
                    .map(OutboundTransport::Chained)
            }
        };

        let transport = match dial_result {
            Ok(t) => t,
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        };

        let mon = MonProxyStream::from_stream(transport, flow_stat);
        let stream = ProxyClientStream::from_stream(context.context(), mon, server.server_config(), target_addr);
        Ok(Self::Proxied(stream))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            Self::Proxied(ref s) => s.get_ref().get_ref().local_addr(),
            Self::Bypassed(ref s) => s.local_addr(),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match *self {
            Self::Proxied(ref s) => s.get_ref().get_ref().set_nodelay(nodelay),
            Self::Bypassed(ref s) => s.set_nodelay(nodelay),
        }
    }
}

impl AutoProxyIo for AutoProxyClientStream {
    fn is_proxied(&self) -> bool {
        matches!(*self, Self::Proxied(..))
    }
}

impl AsyncRead for AutoProxyClientStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_read(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AutoProxyClientStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_flush(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_shutdown(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write_vectored(cx, bufs),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write_vectored(cx, bufs),
        }
    }
}
