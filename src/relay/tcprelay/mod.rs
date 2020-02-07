//! Relay for TCP implementation

// Allow for futures
// Maybe removed in the future
#![allow(clippy::unnecessary_mut_passed)]

use std::{
    io,
    marker::Unpin,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};

use bytes::BytesMut;
use futures::{future::FusedFuture, ready, select, Future};
use log::{debug, error, trace};
use tokio::{
    self,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
    net::TcpStream,
    time::{self, Delay},
};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::Context,
    relay::{socks5::Address, utils::try_timeout},
};

mod aead;
pub mod client;
mod crypto_io;
mod http_local;
pub mod local;
mod monitor;
mod redir_local;
pub mod server;
mod socks5_local;
mod stream;
mod sys;
mod tunnel_local;
mod utils;

pub use self::crypto_io::CryptoStream;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

/// Methods required for a TCP Connection
pub trait TcpConnection {
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
}

impl TcpConnection for TcpStream {
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, nodelay)
    }
}

/// Shadowsocks' Connection
///
/// The only feature: Supports timeout
pub struct Connection<S> {
    // Actual connection socket
    stream: BufReader<S>,
    // Timer instance
    // Read and Write operations shares the same timer
    timer: Option<Delay>,
    // User defined server timeout
    timeout: Option<Duration>,
    // TCP_NODELAY
    nodelay: bool,
    // Written the first packet flag
    //
    // Connection is usually wrapped inside a `CryptoStream`, which will send IV/Nonce within the first data packet.
    // `TCP_NODELAY` is already set on the internal socket for lower handshake latency.
    //
    // After the first packet, if `nodelay` is `false`, `TCP_NODELAY` status should be reset.
    written_first_packet: bool,
}

impl<S> Connection<S>
where
    S: AsyncRead + TcpConnection,
{
    /// Create a Connection with a stream S
    ///
    /// If `timeout` is Some(..), it will set a timer for both read and write operation.
    pub fn new(stream: S, timeout: Option<Duration>) -> Connection<S> {
        // Set `TCP_NODELAY` for quick handshaking
        if let Err(err) = stream.set_nodelay(true) {
            error!("Failed to set TCP_NODELAY on socket, error: {:?}", err);
        }

        Connection {
            stream: BufReader::new(stream),
            timer: None,
            timeout,
            nodelay: false,
            written_first_packet: false,
        }
    }

    /// Set `TCP_NODELAY` on socket
    pub fn set_nodelay(&mut self, nodelay: bool) -> io::Result<()> {
        self.nodelay = nodelay;

        // If first packet hasn't sent, resetting nodelay is delayed
        if self.written_first_packet {
            self.stream.get_ref().set_nodelay(nodelay)?;
        }

        Ok(())
    }
}

impl<S> Connection<S> {
    fn make_timeout_error() -> io::Error {
        use std::io::ErrorKind;
        ErrorKind::TimedOut.into()
    }

    fn poll_timeout(&mut self, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut timer) = self.timer {
                ready!(Pin::new(timer).poll(cx));
                // FIXME: Clear self.timer or not?
                return Poll::Ready(Err(Connection::<S>::make_timeout_error()));
            } else {
                match self.timeout {
                    Some(timeout) => self.timer = Some(time::delay_for(timeout)),
                    None => break,
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn cancel_timeout(&mut self) {
        let _ = self.timer.take();
    }
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + TcpConnection + Unpin,
{
    pub fn split(self) -> (ReadHalf<Connection<S>>, WriteHalf<Connection<S>>) {
        use tokio::io::split;
        split(self)
    }
}

impl<S> Deref for Connection<S>
where
    S: AsyncRead,
{
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.stream.get_ref()
    }
}

impl<S> DerefMut for Connection<S>
where
    S: AsyncRead,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.stream.get_mut()
    }
}

impl<S: Unpin> Unpin for Connection<S> {}

impl<S> AsyncRead for Connection<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_read(cx, buf) {
            Poll::Ready(r) => {
                self.cancel_timeout();
                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_timeout(cx))?;
                Poll::Pending
            }
        }
    }
}

impl<S> AsyncWrite for Connection<S>
where
    S: AsyncRead + AsyncWrite + TcpConnection + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_write(cx, buf) {
            Poll::Ready(r) => {
                self.cancel_timeout();

                if !self.written_first_packet {
                    self.written_first_packet = true;

                    if !self.nodelay {
                        // Reset `TCP_NODELAY`
                        if let Err(err) = self.stream.get_ref().set_nodelay(false) {
                            error!("Failed to reset TCP_NODELAY on socket, error: {:?}", err);
                        }
                    }
                }

                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_timeout(cx))?;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.stream).poll_flush(cx) {
            Poll::Ready(r) => {
                self.cancel_timeout();
                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_timeout(cx))?;
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Secured TcpStream
pub type STcpStream = Connection<TcpStream>;

async fn connect_proxy_server_internal(
    context: &Context,
    orig_svr_addr: &ServerAddr,
    svr_addr: &ServerAddr,
    timeout: Option<Duration>,
) -> io::Result<STcpStream> {
    match svr_addr {
        ServerAddr::SocketAddr(ref addr) => {
            let stream = try_timeout(TcpStream::connect(addr), timeout).await?;
            debug!("Connected proxy {} ({})", orig_svr_addr, addr);
            Ok(STcpStream::new(stream, timeout))
        }
        ServerAddr::DomainName(ref domain, port) => {
            let result = lookup_then!(context, domain.as_str(), *port, false, |addr| {
                match try_timeout(TcpStream::connect(addr), timeout).await {
                    Ok(s) => Ok(STcpStream::new(s, timeout)),
                    Err(e) => {
                        debug!(
                            "Failed to connect proxy {} ({}:{} ({})) try another (err: {})",
                            orig_svr_addr, domain, port, addr, e
                        );
                        Err(e)
                    }
                }
            });

            match result {
                Ok((addr, s)) => {
                    debug!("Connected proxy {} ({}:{} ({}))", orig_svr_addr, domain, port, addr);
                    Ok(s)
                }
                Err(err) => {
                    error!(
                        "Failed to connect proxy {} ({}:{}), {}",
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
        ConfigType::Socks5Local | ConfigType::TunnelLocal | ConfigType::HttpLocal | ConfigType::RedirLocal => {
            svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr())
        }
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
        "Connecting to proxy {} ({}), timeout: {:?}",
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
                    error!("Failed to set TCP_NODELAY on remote socket, error: {:?}", err);
                }

                return Ok(s);
            }
            Err(err) => {
                // Connection failure, retry
                debug!(
                    "Failed to connect {}, retried {} times (last err: {})",
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
        "Failed to connect {}, retried {} times, last_err: {}",
        svr_addr, RETRY_TIMES, last_err
    );
    Err(last_err)
}

/// Handshake logic for ShadowSocks Client
pub async fn proxy_server_handshake(
    context: &Context,
    remote_stream: STcpStream,
    svr_cfg: &ServerConfig,
    relay_addr: &Address,
) -> io::Result<CryptoStream<STcpStream>> {
    let mut stream = CryptoStream::new(context, remote_stream, svr_cfg);

    trace!("Got encrypt stream and going to send addr: {:?}", relay_addr);

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

/// Establish tunnel between server and client
// pub fn tunnel<CF, CFI, SF, SFI>(addr: Address, c2s: CF, s2c: SF) -> impl Future<Item = (), Error = io::Error> + Send
pub async fn tunnel<CF, CFI, SF, SFI>(mut c2s: CF, mut s2c: SF) -> io::Result<()>
where
    CF: Future<Output = io::Result<CFI>> + Unpin + FusedFuture,
    SF: Future<Output = io::Result<SFI>> + Unpin + FusedFuture,
{
    select! {
        r1 = c2s => r1.map(|_| ()),
        r2 = s2c => r2.map(|_| ()),
    }
}

/// Hold the connection until EOF
pub async fn ignore_until_end<R>(r: &mut R) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; BUFFER_SIZE];
    let mut amt = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        amt += n as u64;
    }
    Ok(amt)
}
