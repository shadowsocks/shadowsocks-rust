//! TcpStream wrappers that supports connecting with options

use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{self, Poll},
};

use futures::{future, ready};
use pin_project::pin_project;
use socket2::Socket;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream},
};

use crate::{
    context::Context,
    relay::{socks5::Address, sys::tcp_stream_connect},
    ServerAddr,
};

use super::{AcceptOpts, ConnectOpts};

/// TcpStream for outbound connections
#[pin_project]
pub struct TcpStream(#[pin] TokioTcpStream);

impl TcpStream {
    /// Connects to address
    pub async fn connect_with_opts(addr: &SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
        tcp_stream_connect(addr, opts).await.map(TcpStream)
    }

    /// Connects shadowsocks server
    pub async fn connect_server_with_opts(
        context: &Context,
        addr: &ServerAddr,
        opts: &ConnectOpts,
    ) -> io::Result<TcpStream> {
        let stream = match *addr {
            ServerAddr::SocketAddr(ref addr) => tcp_stream_connect(addr, opts).await?,
            ServerAddr::DomainName(ref domain, port) => {
                lookup_then!(&context, &domain, port, |addr| {
                    tcp_stream_connect(&addr, opts).await
                })?
                .1
            }
        };

        Ok(TcpStream(stream))
    }

    /// Connects proxy remote target
    pub async fn connect_remote_with_opts(
        context: &Context,
        addr: &Address,
        opts: &ConnectOpts,
    ) -> io::Result<TcpStream> {
        let stream = match *addr {
            Address::SocketAddress(ref addr) => tcp_stream_connect(addr, opts).await?,
            Address::DomainNameAddress(ref domain, port) => {
                lookup_then!(&context, &domain, port, |addr| {
                    tcp_stream_connect(&addr, opts).await
                })?
                .1
            }
        };

        Ok(TcpStream(stream))
    }
}

impl Deref for TcpStream {
    type Target = TokioTcpStream;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().0.poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().0.poll_shutdown(cx)
    }
}

impl From<TokioTcpStream> for TcpStream {
    fn from(s: TokioTcpStream) -> TcpStream {
        TcpStream(s)
    }
}

impl Into<TokioTcpStream> for TcpStream {
    fn into(self) -> TokioTcpStream {
        self.0
    }
}

/// `TcpListener` for accepting inbound connections
pub struct TcpListener {
    inner: TokioTcpListener,
    accept_opts: AcceptOpts,
}

impl TcpListener {
    /// Creates a new TcpListener, which will be bound to the specified address.
    pub async fn bind_with_opts(addr: &SocketAddr, accept_opts: AcceptOpts) -> io::Result<TcpListener> {
        let inner = TokioTcpListener::bind(addr).await?;
        Ok(TcpListener { inner, accept_opts })
    }

    /// Create a `TcpListener` from tokio's `TcpListener`
    pub fn from_listener(listener: TokioTcpListener, accept_opts: AcceptOpts) -> TcpListener {
        TcpListener {
            inner: listener,
            accept_opts,
        }
    }

    /// Polls to accept a new incoming connection to this listener.
    pub fn poll_accept(&self, cx: &mut task::Context<'_>) -> Poll<io::Result<(TokioTcpStream, SocketAddr)>> {
        let (stream, peer_addr) = ready!(self.inner.poll_accept(cx))?;
        setsockopt_with_opt(&stream, &self.accept_opts)?;
        Poll::Ready(Ok((stream, peer_addr)))
    }

    /// Accept a new incoming connection to this listener
    pub async fn accept(&self) -> io::Result<(TokioTcpStream, SocketAddr)> {
        future::poll_fn(|cx| self.poll_accept(cx)).await
    }
}

impl Deref for TcpListener {
    type Target = TokioTcpListener;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TcpListener {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket};

#[cfg(unix)]
fn setsockopt_with_opt<F: AsRawFd>(f: &F, opts: &AcceptOpts) -> io::Result<()> {
    let socket = unsafe { Socket::from_raw_fd(f.as_raw_fd()) };

    if let Some(buf_size) = opts.tcp.send_buffer_size {
        socket.set_send_buffer_size(buf_size as usize)?;
    }

    if let Some(buf_size) = opts.tcp.recv_buffer_size {
        socket.set_recv_buffer_size(buf_size as usize)?;
    }

    if opts.tcp.nodelay {
        socket.set_nodelay(true)?;
    }

    let _ = socket.into_raw_fd();
    Ok(())
}

#[cfg(windows)]
fn setsockopt_with_opt<F: AsRawSocket>(f: &F, opts: &AcceptOpts) -> io::Result<()> {
    let socket = unsafe { Socket::from_raw_socket(f.as_raw_socket()) };

    if let Some(buf_size) = opts.tcp.send_buffer_size {
        socket.set_send_buffer_size(buf_size as usize)?;
    }

    if let Some(buf_size) = opts.tcp.recv_buffer_size {
        socket.set_recv_buffer_size(buf_size as usize)?;
    }

    if opts.tcp.nodelay {
        socket.set_nodelay(true)?;
    }

    let _ = socket.into_raw_socket();
    Ok(())
}
