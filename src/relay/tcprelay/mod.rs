//! Relay for TCP implementation

// Allow for futures
// Maybe removed in the future
#![allow(clippy::unnecessary_mut_passed)]

use std::{
    io,
    marker::Unpin,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
    time::Duration,
};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::Context,
    relay::{socks5::Address, utils::try_timeout},
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

mod aead;
pub mod client;
mod context;
mod crypto_io;
pub mod local;
mod monitor;
pub mod server;
mod socks5_local;
mod stream;
mod tunnel_local;
mod utils;

pub use self::crypto_io::CryptoStream;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

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
}

impl<S> Connection<S>
where
    S: AsyncRead,
{
    pub fn new(stream: S, timeout: Option<Duration>) -> Connection<S> {
        Connection {
            stream: BufReader::new(stream),
            timer: None,
            timeout,
        }
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
    S: AsyncRead + AsyncWrite + Unpin,
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
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_write(cx, buf) {
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

pub type STcpStream = Connection<TcpStream>;

async fn connect_proxy_server_internal(
    context: &Context,
    svr_addr: &ServerAddr,
    timeout: Option<Duration>,
) -> io::Result<STcpStream> {
    match svr_addr {
        ServerAddr::SocketAddr(ref addr) => {
            let stream = try_timeout(TcpStream::connect(addr), timeout).await?;
            Ok(STcpStream::new(stream, timeout))
        }
        #[cfg(feature = "trust-dns")]
        ServerAddr::DomainName(ref domain, port) => {
            use crate::relay::dns_resolver::resolve;

            let vec_ipaddr = try_timeout(resolve(context, &domain[..], *port, false), timeout).await?;

            assert!(!vec_ipaddr.is_empty());

            let mut last_err: Option<io::Error> = None;
            for addr in &vec_ipaddr {
                match try_timeout(TcpStream::connect(addr), timeout).await {
                    Ok(s) => return Ok(STcpStream::new(s, timeout)),
                    Err(e) => {
                        error!(
                            "Failed to connect {}:{}, resolved address {}, try another (err: {})",
                            domain, port, addr, e
                        );
                        last_err = Some(e);
                    }
                }
            }

            let err = last_err.unwrap();
            error!(
                "Failed to connect {}:{}, tried all addresses but still failed (last err: {})",
                domain, port, err
            );
            Err(err)
        }
        #[cfg(not(feature = "trust-dns"))]
        ServerAddr::DomainName(ref domain, port) => {
            let stream = try_timeout(TcpStream::connect((domain.as_str(), *port)), timeout).await?;
            Ok(STcpStream::new(stream, timeout))
        }
    }
}

/// Connect to proxy server with `ServerConfig`
async fn connect_proxy_server(context: &Context, svr_cfg: &ServerConfig) -> io::Result<STcpStream> {
    let timeout = svr_cfg.timeout();

    let svr_addr = match context.config().config_type {
        ConfigType::Server => svr_cfg.addr(),
        ConfigType::Local => svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr()),
    };

    // Retry if connect failed
    //
    // FIXME: This won't work if server is actually down.
    //        Probably we should retry with another server.
    //
    // Also works if plugin is starting
    const RETRY_TIMES: i32 = 3;

    trace!("Connecting to proxy {}, timeout: {:?}", svr_addr, timeout);
    let mut last_err = None;
    for retry_time in 0..RETRY_TIMES {
        match connect_proxy_server_internal(context, svr_addr, timeout).await {
            Ok(s) => return Ok(s),
            Err(err) => {
                // Connection failure, retry
                debug!(
                    "Failed to connect {}, retried {} times (last err: {})",
                    svr_addr, retry_time, err
                );
                last_err = Some(err);

                // Retry 100ms later
                time::delay_for(Duration::from_millis(100)).await;
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
    remote_stream: STcpStream,
    svr_cfg: Arc<ServerConfig>,
    relay_addr: &Address,
) -> io::Result<CryptoStream<STcpStream>> {
    let mut stream = CryptoStream::new(remote_stream, svr_cfg.clone());

    trace!("Got encrypt stream and going to send addr: {:?}", relay_addr);

    // Send relay address to remote
    let mut addr_buf = BytesMut::with_capacity(relay_addr.serialized_len());
    relay_addr.write_to_buf(&mut addr_buf);
    stream.write_all(&addr_buf).await?;

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
