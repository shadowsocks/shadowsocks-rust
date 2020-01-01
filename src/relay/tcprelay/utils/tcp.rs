//! TCP API wrappers

use std::{io, mem::MaybeUninit, net::SocketAddr, pin::Pin, task, time::Duration};

use bytes::{Buf, BufMut};
use log::error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net,
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
    inner: net::TcpListener,
}

impl TcpListener {
    /// Creates a new TcpListener which will be bound to the specified address.
    ///
    /// Set `fast_open` to `true` will try to enable TFO (TCP Fast Open)
    pub async fn bind(addr: &SocketAddr, fast_open: bool) -> io::Result<TcpListener> {
        if fast_open {
            tfo::bind_listener(addr).await
        } else {
            net::TcpListener::bind(addr).await
        }
        .map(|inner| TcpListener { inner })
    }

    /// Accept a new incoming connection from this listener.
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        self.inner.accept().await.map(|(s, a)| (TcpStream { inner: s }, a))
    }

    /// Returns the local address that this listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// A TCP stream between a local and a remote socket.
pub struct TcpStream {
    inner: net::TcpStream,
}

impl TcpStream {
    async fn connect(addr: &SocketAddr, fast_open: bool) -> io::Result<TcpStream> {
        if fast_open {
            tfo::connect_stream(addr).await
        } else {
            net::TcpStream::connect(addr).await
        }
        .map(|inner| TcpStream { inner })
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
            ServerAddr::SocketAddr(ref addr) => TcpStream::connect(addr, fast_open).await,
            ServerAddr::DomainName(ref domain, port) => {
                let vec_ipaddr = try_timeout(resolve(ctx, &domain[..], port, false), timeout).await?;
                assert!(!vec_ipaddr.is_empty());

                // Try every addresses
                let mut last_err: Option<io::Error> = None;
                for addr in &vec_ipaddr {
                    match TcpStream::connect(addr, fast_open).await {
                        Ok(s) => return Ok(s),
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
            Address::SocketAddress(ref addr) => TcpStream::connect(addr, fast_open).await,
            Address::DomainNameAddress(ref domain, port) => {
                let vec_ipaddr = try_timeout(resolve(ctx, &domain[..], port, false), timeout).await?;
                assert!(!vec_ipaddr.is_empty());

                // Try every addresses
                let mut last_err: Option<io::Error> = None;
                for addr in &vec_ipaddr {
                    match TcpStream::connect(addr, fast_open).await {
                        Ok(s) => return Ok(s),
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

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut [u8],
    ) -> task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut B,
    ) -> task::Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read_buf(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut B,
    ) -> task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write_buf(cx, buf)
    }
}
