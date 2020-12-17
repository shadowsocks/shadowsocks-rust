//! TcpStream wrappers that supports connecting with options

use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{self, Poll},
};

use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    context::Context,
    relay::{socks5::Address, sys::tcp_stream_connect},
    ServerAddr,
};

use super::connect_opt::ConnectOpts;

/// TcpStream for outbound connections
#[pin_project]
pub struct TcpStream(#[pin] tokio::net::TcpStream);

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
    type Target = tokio::net::TcpStream;

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

impl From<tokio::net::TcpStream> for TcpStream {
    fn from(s: tokio::net::TcpStream) -> TcpStream {
        TcpStream(s)
    }
}

impl Into<tokio::net::TcpStream> for TcpStream {
    fn into(self) -> tokio::net::TcpStream {
        self.0
    }
}
