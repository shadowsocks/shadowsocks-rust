//! TCP connection stream for local server with remote (proxy server or remote target)

use std::{
    fmt::{self, Display, Formatter},
    io::{self, Error},
    net::SocketAddr,
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};

use bytes::{Buf, BufMut, BytesMut};
use futures::ready;
use log::{debug, error, trace};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::{Context, SharedContext},
    relay::{socks5::Address, sys::tcp_stream_connect, utils::try_timeout},
};

use super::{connection::Connection, CryptoStream, STcpStream};

enum ProxiedConnectState {
    Connected(Address),
    Handshaking { buf: BytesMut },
    Established,
}

#[pin_project]
struct ProxiedConnection {
    #[pin]
    stream: CryptoStream<STcpStream>,
    state: ProxiedConnectState,
}

impl ProxiedConnection {
    fn connected(stream: CryptoStream<STcpStream>, addr: Address) -> ProxiedConnection {
        ProxiedConnection {
            stream,
            state: ProxiedConnectState::Connected(addr),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.get_ref().get_ref().local_addr()
    }
}

impl AsyncRead for ProxiedConnection {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxiedConnection {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let this = self.as_mut().project();

            match this.state {
                ProxiedConnectState::Connected(ref addr) => {
                    assert_ne!(data.len(), 0);

                    // Send relay address to remote
                    //
                    // NOTE: `Address` handshake packets are very small in most cases,
                    // so
                    // 1. it will be sent with the IV/Nonce data (implemented inside `CryptoStream`).
                    // 2. concatenating target's Address with the first data buffer (#232)
                    //
                    // For lower latency, first packet should be sent back quickly,
                    // so TCP_NODELAY should be kept enabled until the first data packet is received.

                    // A new buffer must be allocated
                    // CryptoStream will encrypt all data into one packet
                    //
                    // Vectored IO is not applicable here.
                    let addr_len = addr.serialized_len();
                    let mut buf = BytesMut::with_capacity(addr_len + data.len());
                    addr.write_to_buf(&mut buf);
                    buf.put_slice(data);

                    trace!(
                        "sending handshake address {} ({} bytes) with data {} bytes, totally {} bytes",
                        addr,
                        addr_len,
                        data.len(),
                        buf.remaining()
                    );

                    // Fast path
                    //
                    // For CryptoStream (Stream and AEAD), poll_write will return Ready(..) until all data have been sent out
                    match this.stream.poll_write(cx, buf.bytes()) {
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Ready(Ok(n)) => {
                            buf.advance(n);

                            if buf.remaining() < data.len() {
                                // Ok, written some data with Address
                                let written_len = data.len() - buf.remaining();

                                trace!(
                                    "sent handshake address {} ({} bytes) with {} bytes of data, data len {} bytes, totally {} bytes",
                                    addr,
                                    addr_len,
                                    written_len,
                                    data.len(),
                                    n,
                                );

                                self.state = ProxiedConnectState::Established;
                                return Poll::Ready(Ok(written_len));
                            } else {
                                trace!(
                                    "sending handshake address {} ({} bytes) partially {} bytes, data len {} bytes",
                                    addr,
                                    addr_len,
                                    n,
                                    data.len()
                                );
                            }

                            // FALLTHROUGH
                            // Handshaking branch will try to poll_write again
                            self.state = ProxiedConnectState::Handshaking { buf };
                        }
                        Poll::Pending => {
                            // poll_write is not ready, let Handshaking branch try again later
                            self.state = ProxiedConnectState::Handshaking { buf };

                            return Poll::Pending;
                        }
                    }
                }
                ProxiedConnectState::Handshaking { ref mut buf } => {
                    // Try to write at least addr_len size
                    let n = ready!(this.stream.poll_write(cx, buf.bytes()))?;
                    buf.advance(n);

                    if buf.remaining() < data.len() {
                        // Ok, written some data with Address
                        let written_len = data.len() - buf.remaining();

                        trace!(
                            "sent handshake address with {} bytes of data, data len {} bytes, totally {} bytes",
                            written_len,
                            data.len(),
                            n,
                        );

                        self.state = ProxiedConnectState::Established;
                        return Poll::Ready(Ok(written_len));
                    }
                }
                ProxiedConnectState::Established => {
                    break;
                }
            }
        }

        self.project().stream.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}

#[pin_project(project = ProxyConnectionProj)]
enum ProxyConnection {
    Direct(#[pin] STcpStream),
    Proxied(#[pin] ProxiedConnection),
}

impl ProxyConnection {
    /// Check if the underlying connection is proxied
    fn is_proxied(&self) -> bool {
        matches!(*self, ProxyConnection::Proxied { .. })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            ProxyConnection::Direct(ref stream) => stream.get_ref().local_addr(),
            ProxyConnection::Proxied(ref stream) => stream.local_addr(),
        }
    }
}

macro_rules! forward_call {
    ($self:expr, $method:ident $(, $param:expr)*) => {
        match $self.as_mut().project() {
            ProxyConnectionProj::Direct(stream) => stream.$method($($param),*),
            ProxyConnectionProj::Proxied(stream) => stream.$method($($param),*),
        }
    };
}

impl AsyncRead for ProxyConnection {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_read, cx, buf)
    }
}

impl AsyncWrite for ProxyConnection {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // let p = forward_call!(self, poll_write, cx, buf);
        forward_call!(self, poll_write, cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_flush, cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_shutdown, cx)
    }
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

/// Stream wrapper for both direct connections and proxied connections
#[pin_project]
pub struct ProxyStream {
    #[pin]
    connection: ProxyConnection,
    context: SharedContext,
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

        // FIXME: No timeout for direct connections

        let stream = match *addr {
            Address::SocketAddress(ref saddr) => tcp_stream_connect(&saddr, context.config()).await?,
            Address::DomainNameAddress(ref domain, port) => {
                lookup_then!(context, domain, port, |saddr| {
                    tcp_stream_connect(&saddr, context.config()).await
                })?
                .1
            }
        };

        Ok(ProxyStream {
            context,
            connection: ProxyConnection::Direct(Connection::new(stream, None, false)),
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
        let proxy_stream = CryptoStream::new(context.clone(), server_stream, svr_cfg);

        Ok(ProxyStream {
            context,
            connection: ProxyConnection::Proxied(ProxiedConnection::connected(proxy_stream, addr.clone())),
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
        self.connection.local_addr()
    }

    /// Check if the underlying connection is proxied
    pub fn is_proxied(&self) -> bool {
        self.connection.is_proxied()
    }

    /// Get reference to context
    pub fn context(&self) -> &Context {
        &self.context
    }
}

impl AsyncRead for ProxyStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        #[allow(unused_variables)]
        let before_remain = buf.remaining();
        let p = self.as_mut().project().connection.poll_read(cx, buf);

        // Flow statistic for Android client
        #[cfg(feature = "local-flow-stat")]
        {
            if self.is_proxied() {
                if let Poll::Ready(Ok(..)) = p {
                    self.context()
                        .local_flow_statistic()
                        .tcp()
                        .incr_rx(before_remain - buf.remaining());
                }
            }
        }

        p
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let p = self.as_mut().project().connection.poll_write(cx, buf);

        // Flow statistic for Android client
        #[cfg(feature = "local-flow-stat")]
        {
            if self.is_proxied() {
                if let Poll::Ready(Ok(n)) = p {
                    self.context().local_flow_statistic().tcp().incr_tx(n);
                }
            }
        }

        p
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().connection.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().connection.poll_shutdown(cx)
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
            let stream = try_timeout(tcp_stream_connect(&addr, context.config()), timeout).await?;
            trace!("connected proxy {} ({})", orig_svr_addr, addr);
            Ok(STcpStream::new(stream, timeout, true))
        }
        ServerAddr::DomainName(ref domain, port) => {
            let result = lookup_then!(context, domain.as_str(), *port, |addr| {
                match try_timeout(tcp_stream_connect(&addr, context.config()), timeout).await {
                    Ok(s) => Ok(STcpStream::new(s, timeout, true)),
                    Err(e) => {
                        trace!(
                            "failed to connect proxy {} ({}:{} ({})) try another (err: {})",
                            orig_svr_addr,
                            domain,
                            port,
                            addr,
                            e
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
                    debug!(
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
    let timeout = svr_cfg.timeout();

    let svr_addr = match context.config().config_type {
        ConfigType::Server => svr_cfg.addr(),

        ConfigType::Socks5Local => svr_cfg.external_addr(),
        #[cfg(feature = "local-socks4")]
        ConfigType::Socks4Local => svr_cfg.external_addr(),
        #[cfg(feature = "local-tunnel")]
        ConfigType::TunnelLocal => svr_cfg.external_addr(),
        #[cfg(feature = "local-dns")]
        ConfigType::DnsLocal => svr_cfg.external_addr(),
        #[cfg(feature = "local-http")]
        ConfigType::HttpLocal => svr_cfg.external_addr(),
        #[cfg(all(
            feature = "local-http",
            any(feature = "local-http-native-tls", feature = "local-http-rustls")
        ))]
        ConfigType::HttpsLocal => svr_cfg.external_addr(),
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
                trace!(
                    "failed to connect {}, retried {} times (last err: {})",
                    svr_addr,
                    retry_time,
                    err
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
    debug!(
        "failed to connect {}, retried {} times, last_err: {}",
        svr_addr, RETRY_TIMES, last_err
    );
    Err(last_err)
}
