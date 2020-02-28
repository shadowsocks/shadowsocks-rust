//! TCP connection stream for local server with remote (proxy server or remote target)

use std::{
    fmt::{self, Display, Formatter},
    io::{self, Error},
    marker::Unpin,
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use bytes::BytesMut;
use log::{debug, error, trace};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::{Context, SharedContext},
    relay::{socks5::Address, utils::try_timeout, sys::new_tcp_stream},
};

use super::{connection::Connection, CryptoStream, STcpStream};

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
    Direct(STcpStream),
    Proxied(CryptoStream<STcpStream>),
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
        debug!("connect to {} directly (bypassed)", addr);

        // NOTE: Direct connection's timeout is controlled by the global key
        let timeout = context.config().timeout;

        let stream = match *addr {
            Address::SocketAddress(ref saddr) => {
                let stream = new_tcp_stream(&saddr, &context)?;
                TcpStream::connect_std(stream, &saddr).await?
            },
            Address::DomainNameAddress(ref domain, port) => {
                lookup_then!(context, domain, port, |saddr| {
                    let stream = new_tcp_stream(&saddr, &context)?;
                    TcpStream::connect_std(stream, &saddr).await
                })?.1
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

        let server_stream = connect_proxy_server(&*context, svr_cfg).await?;
        let proxy_stream = proxy_server_handshake(context, server_stream, svr_cfg, addr).await?;

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

async fn connect_proxy_server_internal(
    context: &Context,
    orig_svr_addr: &ServerAddr,
    svr_addr: &ServerAddr,
    timeout: Option<Duration>,
) -> io::Result<STcpStream> {
    match svr_addr {
        ServerAddr::SocketAddr(ref addr) => {
            let stream = new_tcp_stream(&addr, &context)?;
            let stream = try_timeout(TcpStream::connect_std(stream, &addr), timeout).await?;
            trace!("connected proxy {} ({})", orig_svr_addr, addr);
            Ok(STcpStream::new(stream, timeout))
        }
        ServerAddr::DomainName(ref domain, port) => {
            let result = lookup_then!(context, domain.as_str(), *port, |addr| {
                let stream = new_tcp_stream(&addr, &context)?;
                match try_timeout(TcpStream::connect_std(stream, &addr), timeout).await {
                    Ok(s) => {
                        Ok(STcpStream::new(s, timeout))
                    },
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
        ConfigType::Socks5Local | ConfigType::TunnelLocal | ConfigType::HttpLocal | ConfigType::RedirLocal => {
            svr_cfg.external_addr()
        }
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
