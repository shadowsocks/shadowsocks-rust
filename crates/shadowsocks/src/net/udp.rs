//! UDP socket wrappers

use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
use std::{
    io::{ErrorKind, IoSlice, IoSliceMut},
    task::{Context as TaskContext, Poll},
};

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
use futures::{future, ready};
use pin_project::pin_project;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
use tokio::io::Interest;

use crate::{context::Context, relay::socks5::Address, ServerAddr};

use super::{
    sys::{create_inbound_udp_socket, create_outbound_udp_socket},
    AcceptOpts,
    AddrFamily,
    ConnectOpts,
};

/// Message struct for `batch_send`
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
pub struct BatchSendMessage<'a> {
    pub addr: Option<SocketAddr>,
    pub data: &'a [IoSlice<'a>],
    pub data_len: usize,
}

/// Message struct for `batch_recv`
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
pub struct BatchRecvMessage<'a> {
    pub addr: SocketAddr,
    pub data: &'a mut [IoSliceMut<'a>],
    pub data_len: usize,
}

/// Wrappers for outbound `UdpSocket`
#[pin_project]
pub struct UdpSocket(#[pin] tokio::net::UdpSocket);

impl UdpSocket {
    /// Connects to shadowsocks server
    pub async fn connect_server_with_opts(
        context: &Context,
        addr: &ServerAddr,
        opts: &ConnectOpts,
    ) -> io::Result<UdpSocket> {
        let socket = match *addr {
            ServerAddr::SocketAddr(ref remote_addr) => {
                let socket = create_outbound_udp_socket(From::from(remote_addr), opts).await?;
                socket.connect(remote_addr).await?;
                socket
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context, dname, port, |remote_addr| {
                    let s = create_outbound_udp_socket(From::from(&remote_addr), opts).await?;
                    s.connect(remote_addr).await.map(|_| s)
                })?
                .1
            }
        };

        Ok(UdpSocket(socket))
    }

    /// Connects to proxy target
    pub async fn connect_remote_with_opts(
        context: &Context,
        addr: &Address,
        opts: &ConnectOpts,
    ) -> io::Result<UdpSocket> {
        let socket = match *addr {
            Address::SocketAddress(ref remote_addr) => {
                let socket = create_outbound_udp_socket(From::from(remote_addr), opts).await?;
                socket.connect(remote_addr).await?;
                socket
            }
            Address::DomainNameAddress(ref dname, port) => {
                lookup_then!(context, dname, port, |remote_addr| {
                    let s = create_outbound_udp_socket(From::from(&remote_addr), opts).await?;
                    s.connect(remote_addr).await.map(|_| s)
                })?
                .1
            }
        };

        Ok(UdpSocket(socket))
    }

    /// Connects to shadowsocks server
    pub async fn connect_with_opts(addr: &SocketAddr, opts: &ConnectOpts) -> io::Result<UdpSocket> {
        let socket = create_outbound_udp_socket(From::from(addr), opts).await?;
        socket.connect(addr).await?;
        Ok(UdpSocket(socket))
    }

    /// Binds to a specific address (inbound)
    #[inline]
    pub async fn listen(addr: &SocketAddr) -> io::Result<UdpSocket> {
        UdpSocket::listen_with_opts(addr, AcceptOpts::default()).await
    }

    /// Binds to a specific address (inbound)
    pub async fn listen_with_opts(addr: &SocketAddr, opts: AcceptOpts) -> io::Result<UdpSocket> {
        let socket = create_inbound_udp_socket(addr, opts.ipv6_only).await?;
        Ok(UdpSocket(socket))
    }

    /// Binds to a specific address with opts
    pub async fn connect_any_with_opts<AF: Into<AddrFamily>>(af: AF, opts: &ConnectOpts) -> io::Result<UdpSocket> {
        create_outbound_udp_socket(af.into(), opts).await.map(UdpSocket)
    }

    /// Batch send packets
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn poll_batch_send(
        &self,
        cx: &mut TaskContext<'_>,
        msgs: &mut [BatchSendMessage<'_>],
    ) -> Poll<io::Result<usize>> {
        use super::sys::batch_sendmsg;

        loop {
            ready!(self.0.poll_send_ready(cx))?;

            match self.0.try_io(Interest::WRITABLE, || batch_sendmsg(&self.0, msgs)) {
                Ok(n) => return Ok(n).into(),
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).into(),
            }
        }
    }

    /// Batch send packets
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub async fn batch_send(&self, msgs: &mut [BatchSendMessage<'_>]) -> io::Result<usize> {
        future::poll_fn(|cx| self.poll_batch_send(cx, msgs)).await
    }

    /// Batch recv packets
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub fn poll_batch_recv(
        &self,
        cx: &mut TaskContext<'_>,
        msgs: &mut [BatchRecvMessage<'_>],
    ) -> Poll<io::Result<usize>> {
        use super::sys::batch_recvmsg;

        loop {
            ready!(self.0.poll_recv_ready(cx))?;

            match self.0.try_io(Interest::READABLE, || batch_recvmsg(&self.0, msgs)) {
                Ok(n) => return Ok(n).into(),
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).into(),
            }
        }
    }

    /// Batch recv packets
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    pub async fn batch_recv(&self, msgs: &mut [BatchRecvMessage<'_>]) -> io::Result<usize> {
        future::poll_fn(|cx| self.poll_batch_recv(cx, msgs)).await
    }
}

impl Deref for UdpSocket {
    type Target = tokio::net::UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UdpSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<tokio::net::UdpSocket> for UdpSocket {
    fn from(s: tokio::net::UdpSocket) -> Self {
        UdpSocket(s)
    }
}

impl From<UdpSocket> for tokio::net::UdpSocket {
    fn from(s: UdpSocket) -> tokio::net::UdpSocket {
        s.0
    }
}
