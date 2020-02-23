//! TCP connection stream for local server with remote (proxy server or remote target)

use std::{
    fmt::{self, Display, Formatter},
    io::{self, Error},
    marker::Unpin,
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use log::trace;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    net::TcpStream,
};

use crate::{
    config::ServerConfig,
    context::{Context, SharedContext},
    relay::socks5::Address,
};

use super::{connection::Connection, CryptoStream};

macro_rules! forward_call {
    ($self:expr, $method:ident $(, $param:expr)*) => {
        match *$self {
            ProxyStream::Direct(ref mut s) => Pin::new(s).$method($($param),*),
            ProxyStream::Proxied(ref mut s) => Pin::new(s).$method($($param),*),
        }
    };
}

/// Stream wrapper for both direct connections and proxied connections
#[allow(clippy::large_enum_variant)]
pub enum ProxyStream {
    Direct(Connection<TcpStream>),
    Proxied(CryptoStream<Connection<TcpStream>>),
}

#[derive(Debug)]
pub struct ProxyStreamError {
    inner: Error,
    bypassed: bool,
}

impl ProxyStreamError {
    fn new(inner: Error, bypassed: bool) -> ProxyStreamError {
        ProxyStreamError { inner, bypassed }
    }

    /// Check if it is proxied
    pub fn is_proxied(&self) -> bool {
        self.bypassed
    }

    /// Into internal `std::io::Error`
    pub fn into_inner(self) -> Error {
        self.inner
    }
}

impl From<ProxyStreamError> for Error {
    fn from(err: ProxyStreamError) -> Error {
        err.inner
    }
}

impl Display for ProxyStreamError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl ProxyStream {
    /// Connect to remote by ACL rules
    pub async fn connect(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: &Address,
    ) -> Result<ProxyStream, ProxyStreamError> {
        if context.check_target_bypassed(addr).await {
            ProxyStream::connect_direct_wrapped(&*context, addr).await
        } else {
            ProxyStream::connect_proxied_wrapped(context, svr_cfg, addr).await
        }
    }

    /// Connect to remote directly (without proxy)
    ///
    /// This is used for hosts that matches ACL bypassed rules
    pub async fn connect_direct(context: &Context, addr: &Address) -> io::Result<ProxyStream> {
        trace!("connect to {} directly (bypassed)", addr);

        // NOTE: Direct connection's timeout is controlled by the global key
        let timeout = context.config().timeout;

        let stream = match *addr {
            Address::SocketAddress(ref saddr) => TcpStream::connect(saddr).await?,
            Address::DomainNameAddress(ref domain, port) => {
                lookup_then!(context, domain, port, |saddr| { TcpStream::connect(saddr).await })?.1
            }
        };

        Ok(ProxyStream::Direct(Connection::new(stream, timeout)))
    }

    async fn connect_direct_wrapped(context: &Context, addr: &Address) -> Result<ProxyStream, ProxyStreamError> {
        match ProxyStream::connect_direct(context, addr).await {
            Ok(s) => Ok(s),
            Err(err) => Err(ProxyStreamError::new(err, true)),
        }
    }

    /// Connect to remote through proxy server
    ///
    /// This is used for hosts that matches ACL proxied rules
    pub async fn connect_proxied(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: &Address,
    ) -> io::Result<ProxyStream> {
        trace!("connect to {} through {} (proxied)", addr, svr_cfg.addr());

        let server_stream = super::local::connect_proxy_server(&*context, svr_cfg).await?;
        let proxy_stream = super::local::proxy_server_handshake(context, server_stream, svr_cfg, addr).await?;

        Ok(ProxyStream::Proxied(proxy_stream))
    }

    async fn connect_proxied_wrapped(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: &Address,
    ) -> Result<ProxyStream, ProxyStreamError> {
        match ProxyStream::connect_proxied(context, svr_cfg, addr).await {
            Ok(s) => Ok(s),
            Err(err) => Err(ProxyStreamError::new(err, false)),
        }
    }

    /// Split into reader and writer
    pub fn split(self) -> (ReadHalf<ProxyStream>, WriteHalf<ProxyStream>) {
        use tokio::io::split;
        split(self)
    }

    /// Returns the local socket address of this stream socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            ProxyStream::Direct(ref s) => s.get_ref().local_addr(),
            ProxyStream::Proxied(ref s) => s.get_ref().get_ref().local_addr(),
        }
    }

    /// Check if the underlying connection is proxied
    pub fn is_proxied(&self) -> bool {
        match *self {
            ProxyStream::Proxied(..) => true,
            _ => false,
        }
    }
}

impl Unpin for ProxyStream {}

impl AsyncRead for ProxyStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        forward_call!(self, poll_read, cx, buf)
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        forward_call!(self, poll_write, cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_flush, cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_shutdown, cx)
    }
}
