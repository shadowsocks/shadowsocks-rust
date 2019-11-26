//! Relay for TCP implementation

use std::{
    io,
    marker::Unpin,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::SharedContext,
    relay::{dns_resolver::resolve, socks5::Address, utils::try_timeout},
};

use bytes::BytesMut;
use futures::{
    future::{self, FusedFuture, Pending},
    ready, select, Future,
};
use log::{error, trace};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpStream,
    prelude::*,
    time::{self, Timeout},
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
mod utils;

pub use self::crypto_io::CryptoStream;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

pub struct Connection<S> {
    stream: S,
    read_timer: Option<Timeout<Pending<()>>>,
    write_timer: Option<Timeout<Pending<()>>>,
    timeout: Option<Duration>,
}

impl<S> Connection<S> {
    pub fn new(stream: S, timeout: Option<Duration>) -> Connection<S> {
        Connection {
            stream: stream,
            read_timer: None,
            write_timer: None,
            timeout: timeout,
        }
    }

    fn poll_read_timeout(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut timer) = self.read_timer {
                ready!(Pin::new(timer).poll(cx))?;
            } else {
                match self.timeout {
                    Some(timeout) => self.read_timer = Some(time::timeout(timeout, future::pending())),
                    None => break,
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_write_timeout(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut timer) = self.write_timer {
                ready!(Pin::new(timer).poll(cx))?;
            } else {
                match self.timeout {
                    Some(timeout) => self.write_timer = Some(time::timeout(timeout, future::pending())),
                    None => break,
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn cancel_read_timeout(&mut self) {
        let _ = self.read_timer.take();
    }

    fn cancel_write_timeout(&mut self) {
        let _ = self.write_timer.take();
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

impl<S> Deref for Connection<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<S> DerefMut for Connection<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl<S: Unpin> Unpin for Connection<S> {}

impl<S> AsyncRead for Connection<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_read(cx, buf) {
            Poll::Ready(r) => {
                self.cancel_read_timeout();
                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_read_timeout(cx))?;
                Poll::Pending
            }
        }
    }
}

impl<S> AsyncWrite for Connection<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.stream).poll_write(cx, buf) {
            Poll::Ready(r) => {
                self.cancel_write_timeout();
                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_write_timeout(cx))?;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.stream).poll_flush(cx) {
            Poll::Ready(r) => {
                self.cancel_write_timeout();
                Poll::Ready(r)
            }
            Poll::Pending => {
                ready!(self.poll_write_timeout(cx))?;
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub type STcpStream = Connection<TcpStream>;

/// Connect to proxy server with `ServerConfig`
async fn connect_proxy_server(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> io::Result<STcpStream> {
    let timeout = svr_cfg.timeout();

    let svr_addr = match context.config().config_type {
        ConfigType::Server => svr_cfg.addr(),
        ConfigType::Local => svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr()),
    };

    trace!("Connecting to proxy {:?}, timeout: {:?}", svr_addr, timeout);
    match svr_addr {
        ServerAddr::SocketAddr(ref addr) => {
            let stream = try_timeout(TcpStream::connect(addr), timeout).await?;
            Ok(STcpStream::new(stream, timeout))
        }
        ServerAddr::DomainName(ref domain, port) => {
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
    }
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

    // let addr = Arc::new(addr);

    // let cloned_addr = addr.clone();
    // let c2s = c2s.then(move |res| {
    //     match res {
    //         Ok(..) => {
    //             // Continue reading response from remote server
    //             trace!("Relay {} client -> server is finished", cloned_addr);

    //             Ok(TunnelDirection::Client2Server)
    //         }
    //         Err(err) => {
    //             error!("Relay {} client -> server aborted: {}", cloned_addr, err);
    //             Err(err)
    //         }
    //     }
    // });

    // let cloned_addr = addr.clone();
    // let s2c = s2c.then(move |res| match res {
    //     Ok(..) => {
    //         trace!("Relay {} client <- server is finished", cloned_addr);

    //         Ok(TunnelDirection::Server2Client)
    //     }
    //     Err(err) => {
    //         error!("Relay {} client <- server aborted: {}", cloned_addr, err);
    //         Err(err)
    //     }
    // });

    // c2s.select(s2c)
    //     .and_then(move |(dir, _)| {
    //         match dir {
    //             TunnelDirection::Server2Client => trace!("Relay {} client <- server is closed, abort connection", addr),
    //             TunnelDirection::Client2Server => trace!("Relay {} server -> client is closed, abort connection", addr),
    //         }

    //         Ok(())
    //     })
    //     .map_err(|(err, _)| err)
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
