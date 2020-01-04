//! TCP API wrappers

use std::{
    io,
    mem::MaybeUninit,
    net::SocketAddr,
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};

use bytes::{Buf, BufMut};
use log::{error, trace};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream},
};

use crate::{
    config::ServerAddr,
    context::Context,
    relay::{dns_resolver::resolve, socks5::Address, utils::try_timeout},
};

use super::{
    split::{split, ReadHalf, WriteHalf},
    tfo,
};

/// A TCP socket server, listening for connections.
pub struct TcpListener {
    inner: TokioTcpListener,
}

impl TcpListener {
    /// Creates a new TcpListener which will be bound to the specified address.
    ///
    /// Set `fast_open` to `true` will try to enable TFO (TCP Fast Open)
    pub async fn bind(addr: &SocketAddr, fast_open: bool) -> io::Result<TcpListener> {
        if fast_open {
            tfo::bind_listener(addr).await
        } else {
            TokioTcpListener::bind(addr).await
        }
        .map(|inner| TcpListener { inner })
    }

    /// Accept a new incoming connection from this listener.
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        self.inner
            .accept()
            .await
            .map(|(s, a)| (TcpStream::from_tokio_stream(s), a))
    }

    /// Returns the local address that this listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// A TCP stream between a local and a remote socket.
pub struct TcpStream {
    inner: TokioTcpStream,

    // For TFO connect
    // Some operating systems require calling specific APIs to perform actual connect
    // with payload data. So we should keep the remote address here and use it in the
    // first call of poll_write
    connect_context: Option<tfo::ConnectContext>,
}

impl TcpStream {
    fn new(inner: TokioTcpStream, connect_context: tfo::ConnectContext) -> TcpStream {
        TcpStream {
            inner,
            connect_context: Some(connect_context),
        }
    }

    fn from_tokio_stream(inner: TokioTcpStream) -> TcpStream {
        TcpStream {
            inner,
            connect_context: None,
        }
    }

    async fn connect(addr: &SocketAddr, fast_open: bool) -> io::Result<TcpStream> {
        if fast_open {
            tfo::connect_stream(addr).await.map(|(s, c)| TcpStream::new(s, c))
        } else {
            TokioTcpStream::connect(addr).await.map(TcpStream::from_tokio_stream)
        }
    }

    /// Opens a TCP connection to a remote host.
    ///
    /// Set `fast_open` to `true` will try to enable TFO (TCP Fast Open)
    pub async fn connect_server(
        ctx: &Context,
        svr_addr: &ServerAddr,
        timeout: Option<Duration>,
        fast_open: bool,
    ) -> io::Result<TcpStream> {
        match *svr_addr {
            ServerAddr::SocketAddr(ref addr) => {
                let s = TcpStream::connect(addr, fast_open).await?;
                trace!("Connected proxy server {}", svr_addr);
                Ok(s)
            }
            ServerAddr::DomainName(ref domain, port) => {
                let vec_ipaddr = try_timeout(resolve(ctx, &domain[..], port, false), timeout).await?;
                assert!(!vec_ipaddr.is_empty());

                // Try every addresses
                let mut last_err: Option<io::Error> = None;
                for addr in &vec_ipaddr {
                    match TcpStream::connect(addr, fast_open).await {
                        Ok(s) => {
                            trace!("Connected proxy server {}:{} (resolved: {})", domain, port, addr);
                            return Ok(s);
                        }
                        Err(e) => {
                            error!(
                                "Failed to connect {}:{} (resolved: {}), try another (err: {})",
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

    /// Opens a TCP connection to a remote host.
    ///
    /// Set `fast_open` to `true` will try to enable TFO (TCP Fast Open)
    pub async fn connect_remote(
        ctx: &Context,
        svr_addr: &Address,
        timeout: Option<Duration>,
        fast_open: bool,
    ) -> io::Result<TcpStream> {
        match *svr_addr {
            Address::SocketAddress(ref addr) => {
                let s = TcpStream::connect(addr, fast_open).await?;
                trace!("Connected remote server {}", svr_addr);
                Ok(s)
            }
            Address::DomainNameAddress(ref domain, port) => {
                let vec_ipaddr = try_timeout(resolve(ctx, &domain[..], port, false), timeout).await?;
                assert!(!vec_ipaddr.is_empty());

                // Try every addresses
                let mut last_err: Option<io::Error> = None;
                for addr in &vec_ipaddr {
                    match TcpStream::connect(addr, fast_open).await {
                        Ok(s) => {
                            trace!("Connected remote server {}:{} (resolved: {})", domain, port, addr);
                            return Ok(s);
                        }
                        Err(e) => {
                            error!(
                                "Failed to connect {}:{} (resolved: {}), try another (err: {})",
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

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the remote address that this stream is connected to.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Gets the value of the TCP_NODELAY option on this socket.
    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    /// Returns whether keepalive messages are enabled on this socket, and if so the duration of time between them.
    pub fn keepalive(&self) -> io::Result<Option<Duration>> {
        self.inner.keepalive()
    }

    /// Sets whether keepalive messages are enabled to be sent on this socket.
    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> io::Result<()> {
        self.inner.set_keepalive(keepalive)
    }

    /// Split a TcpStream into a read half and a write half, which can be used to read and write the stream concurrently.
    pub fn split(&mut self) -> (ReadHalf, WriteHalf) {
        split(self)
    }
}

impl AsyncRead for TcpStream {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        self.inner.prepare_uninitialized_buffer(buf)
    }

    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read_buf(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(cc) = self.connect_context.take() {
            // For TFO, first send has something different between operating systems
            Poll::Ready(cc.connect_with_data(buf))
        } else {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_buf(cx, buf)
    }
}

#[cfg(unix)]
mod sys {
    use super::{TcpListener, TcpStream};
    use std::os::unix::prelude::*;

    impl AsRawFd for TcpStream {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }

    impl AsRawFd for TcpListener {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }
}
