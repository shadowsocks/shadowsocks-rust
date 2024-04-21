//! A `ProxyStream` that bypasses or proxies data through proxy server automatically

use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use pin_project::pin_project;
use shadowsocks::{
    net::{ConnectOpts, TcpStream},
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    local::{context::ServiceContext, loadbalancing::ServerIdent},
    net::MonProxyStream,
};

use super::auto_proxy_io::AutoProxyIo;

/// Unified stream for bypassed and proxied connections
#[allow(clippy::large_enum_variant)]
#[pin_project(project = AutoProxyClientStreamProj)]
pub enum AutoProxyClientStream {
    Proxied(#[pin] ProxyClientStream<MonProxyStream<TcpStream>>),
    Bypassed(#[pin] TcpStream),
}

impl AutoProxyClientStream {
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        AutoProxyClientStream::connect_with_opts(context.clone(), server, addr, context.connect_opts_ref()).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        opts: &ConnectOpts,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        let addr = addr.into();
        if context.check_target_bypassed(&addr).await {
            AutoProxyClientStream::connect_bypassed_with_opts(context, addr, opts).await
        } else {
            AutoProxyClientStream::connect_proxied_with_opts(context, server, addr, opts).await
        }
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed<A>(context: Arc<ServiceContext>, addr: A) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        AutoProxyClientStream::connect_bypassed_with_opts(context.clone(), addr, context.connect_opts_ref()).await
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed_with_opts<A>(
        context: Arc<ServiceContext>,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        // Connect directly.
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        let stream = TcpStream::connect_remote_with_opts(context.context_ref(), &addr, connect_opts).await?;
        Ok(AutoProxyClientStream::Bypassed(stream))
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        AutoProxyClientStream::connect_proxied_with_opts(context.clone(), server, addr, context.connect_opts_ref())
            .await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        let flow_stat = context.flow_stat();
        let stream = match ProxyClientStream::connect_with_opts_map(
            context.context(),
            server.server_config(),
            addr,
            connect_opts,
            |stream| MonProxyStream::from_stream(stream, flow_stat),
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        };
        Ok(AutoProxyClientStream::Proxied(stream))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.get_ref().get_ref().local_addr(),
            AutoProxyClientStream::Bypassed(ref s) => s.local_addr(),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.get_ref().get_ref().set_nodelay(nodelay),
            AutoProxyClientStream::Bypassed(ref s) => s.set_nodelay(nodelay),
        }
    }
}

impl AutoProxyIo for AutoProxyClientStream {
    fn is_proxied(&self) -> bool {
        matches!(*self, AutoProxyClientStream::Proxied(..))
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

impl From<ProxyClientStream<MonProxyStream<TcpStream>>> for AutoProxyClientStream {
    fn from(s: ProxyClientStream<MonProxyStream<TcpStream>>) -> Self {
        AutoProxyClientStream::Proxied(s)
    }
}
