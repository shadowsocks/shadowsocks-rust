use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::{Deref, DerefMut},
    os::fd::AsRawFd,
    pin::Pin,
    task::{self, Poll},
};

use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};

use crate::net::{
    sys::{set_common_sockopt_after_connect, set_common_sockopt_for_connect, ErrorKind},
    AcceptOpts, AddrFamily, ConnectOpts,
};

/// A wrapper of `TcpStream`
#[pin_project]
pub struct TcpStream(#[pin] TokioTcpStream);

impl TcpStream {
    pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        set_common_sockopt_for_connect(addr, &socket, opts)?;

        let stream = socket.connect(addr).await?;
        set_common_sockopt_after_connect(&stream, opts)?;
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

/// Disable IP fragmentation
#[inline]
pub fn set_disable_ip_fragmentation<S: AsRawFd>(_af: AddrFamily, _socket: &S) -> io::Result<()> {
    Ok(())
}

/// Create a `UdpSocket` with specific address family
#[inline]
pub async fn create_outbound_udp_socket(af: AddrFamily, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, config.bind_local_addr) {
        (AddrFamily::Ipv4, Some(SocketAddr::V4(addr))) => addr.into(),
        (AddrFamily::Ipv6, Some(SocketAddr::V6(addr))) => addr.into(),
        (AddrFamily::Ipv4, ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (AddrFamily::Ipv6, ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    bind_outbound_udp_socket(&bind_addr, config).await
}

/// Create a `UdpSocket` binded to `bind_addr`
pub async fn bind_outbound_udp_socket(bind_addr: &SocketAddr, _config: &ConnectOpts) -> io::Result<UdpSocket> {
    let af = AddrFamily::from(bind_addr);

    let socket = UdpSocket::bind(bind_addr).await?;
    let _ = set_disable_ip_fragmentation(af, &socket);

    Ok(socket)
}

/// Enable TCP Fast Open
pub fn set_tcp_fastopen<S: AsRawFd>(_: &S) -> io::Result<()> {
    let err = io::Error::new(ErrorKind::Other, "TFO is not supported in this platform");
    Err(err)
}

/// Create a TCP socket for listening
pub async fn create_inbound_tcp_socket(bind_addr: &SocketAddr, _accept_opts: &AcceptOpts) -> io::Result<TcpSocket> {
    match bind_addr {
        SocketAddr::V4(..) => TcpSocket::new_v4(),
        SocketAddr::V6(..) => TcpSocket::new_v6(),
    }
}
