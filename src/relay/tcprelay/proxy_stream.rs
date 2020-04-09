//! TCP connection stream for local server with remote (proxy server or remote target)

use std::{
    fmt::{self, Display, Formatter},
    io::{self, Error},
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use bytes::BytesMut;
use log::{debug, error, trace};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::{Context, SharedContext},
    relay::{socks5::Address, sys::tcp_stream_connect, utils::try_timeout},
};

use super::{connection::Connection, CryptoStream, STcpStream};

/// Stream wrapper for both direct connections and proxied connections
#[allow(clippy::large_enum_variant)]
#[pin_project]
pub enum ProxyStream {
    Direct {
        #[pin]
        stream: STcpStream,
        context: SharedContext,
    },
    Proxied {
        #[pin]
        stream: CryptoStream<STcpStream>,
        context: SharedContext,
    },
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
            ProxyStream::connect_direct_wrapped(context, addr).await
        } else {
            ProxyStream::connect_proxied_wrapped(context, svr_cfg, addr).await
        }
    }

    /// Connect to remote directly (without proxy)
    ///
    /// This is used for hosts that matches ACL bypassed rules
    pub async fn connect_direct(context: SharedContext, addr: &Address) -> io::Result<ProxyStream> {
        debug!("connect to {} directly (bypassed)", addr);

        // NOTE: Direct connection's timeout is controlled by the global key
        let timeout = context.config().timeout;

        let stream = match *addr {
            Address::SocketAddress(ref saddr) => try_timeout(tcp_stream_connect(&saddr, &context), timeout).await?,
            Address::DomainNameAddress(ref domain, port) => {
                lookup_then!(context, domain, port, |saddr| {
                    try_timeout(tcp_stream_connect(&saddr, &context), timeout).await
                })?
                .1
            }
        };

        Ok(ProxyStream::Direct {
            stream: Connection::new(stream, timeout),
            context,
        })
    }

    async fn connect_direct_wrapped(context: SharedContext, addr: &Address) -> Result<ProxyStream, ProxyStreamError> {
        match ProxyStream::connect_direct(context, addr).await {
            Ok(s) => Ok(s),
            Err(err) => Err(ProxyStreamError::new(err, true)),
        }
    }

    /// Connect to remote via proxy server
    ///
    /// This is used for hosts that matches ACL proxied rules
    pub async fn connect_proxied(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        addr: &Address,
    ) -> io::Result<ProxyStream> {
        debug!(
            "connect to {} via {} ({}) (proxied)",
            addr,
            svr_cfg.addr(),
            svr_cfg.external_addr()
        );

        let server_stream = connect_proxy_server(&context, svr_cfg).await?;
        let proxy_stream = proxy_server_handshake(context.clone(), server_stream, svr_cfg, addr).await?;

        Ok(ProxyStream::Proxied {
            stream: proxy_stream,
            context,
        })
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
            ProxyStream::Direct { ref stream, .. } => stream.get_ref().local_addr(),
            ProxyStream::Proxied { ref stream, .. } => stream.get_ref().get_ref().local_addr(),
        }
    }

    /// Check if the underlying connection is proxied
    pub fn is_proxied(&self) -> bool {
        match *self {
            ProxyStream::Proxied { .. } => true,
            _ => false,
        }
    }

    /// Get reference to context
    pub fn context(&self) -> &Context {
        match *self {
            ProxyStream::Direct { ref context, .. } => &context,
            ProxyStream::Proxied { ref context, .. } => &context,
        }
    }
}

macro_rules! forward_call {
    ($self:expr, $method:ident $(, $param:expr)*) => {
        match $self.as_mut().project() {
            __ProxyStreamProjection::Direct { stream, .. } => stream.$method($($param),*),
            __ProxyStreamProjection::Proxied { stream, .. } => stream.$method($($param),*),
        }
    };
}

impl AsyncRead for ProxyStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let p = forward_call!(self, poll_read, cx, buf);

        // Flow statistic for Android client
        #[cfg(feature = "local-flow-stat")]
        {
            if self.is_proxied() {
                if let Poll::Ready(Ok(n)) = p {
                    self.context().local_flow_statistic().tcp().incr_tx(n as u64);
                }
            }
        }

        p
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let p = forward_call!(self, poll_write, cx, buf);

        // Flow statistic for Android client
        #[cfg(feature = "local-flow-stat")]
        {
            if self.is_proxied() {
                if let Poll::Ready(Ok(n)) = p {
                    self.context().local_flow_statistic().tcp().incr_rx(n as u64);
                }
            }
        }

        p
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_flush, cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_shutdown, cx)
    }
}

async fn connect_proxy_server_internal(
    context: &Context,
    orig_svr_addr: &ServerAddr,
    svr_addr: &ServerAddr,
    timeout: Option<Duration>,
) -> io::Result<STcpStream> {
    match svr_addr {
        ServerAddr::SocketAddr(ref addr) => {
            let stream = try_timeout(tcp_stream_connect(&addr, &context), timeout).await?;
            trace!("connected proxy {} ({})", orig_svr_addr, addr);
            Ok(STcpStream::new(stream, timeout))
        }
        ServerAddr::DomainName(ref domain, port) => {
            let result = lookup_then!(context, domain.as_str(), *port, |addr| {
                match try_timeout(tcp_stream_connect(&addr, &context), timeout).await {
                    Ok(s) => Ok(STcpStream::new(s, timeout)),
                    Err(e) => {
                        debug!(
                            "failed to connect proxy {} ({}:{} ({})) try another (err: {})",
                            orig_svr_addr, domain, port, addr, e
                        );
                        Err(e)
                    }
                }
            });

            match result {
                Ok((addr, s)) => {
                    trace!("connected proxy {} ({}:{} ({}))", orig_svr_addr, domain, port, addr);
                    Ok(s)
                }
                Err(err) => {
                    error!(
                        "failed to connect proxy {} ({}:{}), {}",
                        orig_svr_addr, domain, port, err
                    );
                    Err(err)
                }
            }
        }
    }
}

/// Connect to proxy server with `ServerConfig`
async fn connect_proxy_server(context: &Context, svr_cfg: &ServerConfig) -> io::Result<STcpStream> {
    let timeout = svr_cfg.timeout().or(context.config().timeout);

    let svr_addr = match context.config().config_type {
        ConfigType::Server => svr_cfg.addr(),
        ConfigType::Socks5Local | ConfigType::TunnelLocal | ConfigType::DnsLocal => svr_cfg.external_addr(),
        #[cfg(feature = "local-http")]
        ConfigType::HttpLocal => svr_cfg.external_addr(),
        #[cfg(feature = "local-redir")]
        ConfigType::RedirLocal => svr_cfg.external_addr(),
        ConfigType::Manager => unreachable!("ConfigType::Manager shouldn't need to connect to proxy server"),
    };

    // Retry if connect failed
    //
    // FIXME: This won't work if server is actually down.
    //        Probably we should retry with another server.
    //
    // Also works if plugin is starting
    const RETRY_TIMES: i32 = 3;

    let orig_svr_addr = svr_cfg.addr();
    trace!(
        "connecting to proxy {} ({}), timeout: {:?}",
        orig_svr_addr,
        svr_addr,
        timeout
    );

    let mut last_err = None;
    for retry_time in 0..RETRY_TIMES {
        match connect_proxy_server_internal(context, orig_svr_addr, svr_addr, timeout).await {
            Ok(mut s) => {
                // IMPOSSIBLE, won't fail, but just a guard
                if let Err(err) = s.set_nodelay(context.config().no_delay) {
                    error!("failed to set TCP_NODELAY on remote socket, error: {:?}", err);
                }

                return Ok(s);
            }
            Err(err) => {
                // Connection failure, retry
                debug!(
                    "failed to connect {}, retried {} times (last err: {})",
                    svr_addr, retry_time, err
                );
                last_err = Some(err);

                // Yield and let the others' run
                //
                // It may take some time for scheduler to resume this coroutine.
                tokio::task::yield_now().await;
            }
        }
    }

    let last_err = last_err.unwrap();
    error!(
        "failed to connect {}, retried {} times, last_err: {}",
        svr_addr, RETRY_TIMES, last_err
    );
    Err(last_err)
}

/// Handshake logic for ShadowSocks Client
async fn proxy_server_handshake(
    context: SharedContext,
    remote_stream: STcpStream,
    svr_cfg: &ServerConfig,
    relay_addr: &Address,
) -> io::Result<CryptoStream<STcpStream>> {
    let mut stream = CryptoStream::new(context, remote_stream, svr_cfg);

    trace!("got encrypt stream and going to send addr: {:?}", relay_addr);

    // Send relay address to remote
    //
    // NOTE: `Address` handshake packets are very small in most cases,
    // so it will be sent with the IV/Nonce data (implemented inside `CryptoStream`).
    //
    // For lower latency, first packet should be sent back quickly,
    // so TCP_NODELAY should be kept enabled until the first data packet is received.
    let mut addr_buf = BytesMut::with_capacity(relay_addr.serialized_len());
    relay_addr.write_to_buf(&mut addr_buf);
    stream.write_all(&addr_buf).await?;

    // Here we should keep the TCP_NODELAY set until the first packet is received.
    // https://github.com/shadowsocks/shadowsocks-libev/pull/746
    //
    // Reset TCP_NODELAY after the first packet is received and sent back.

    Ok(stream)
}
