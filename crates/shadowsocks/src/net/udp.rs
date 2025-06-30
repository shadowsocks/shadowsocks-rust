//! UDP socket wrappers

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
))]
use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    task::{Context as TaskContext, Poll},
};

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
))]
use futures::future;
use futures::ready;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
))]
use tokio::io::Interest;
use tokio::{io::ReadBuf, net::ToSocketAddrs};

use crate::{context::Context, relay::socks5::Address, ServerAddr};

use super::{
    sys::{bind_outbound_udp_socket, create_inbound_udp_socket, create_outbound_udp_socket},
    AcceptOpts, AddrFamily, ConnectOpts,
};

/// Message struct for `batch_send`
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
))]
pub struct BatchSendMessage<'a> {
    /// Optional target address
    pub addr: Option<SocketAddr>,
    /// Data to be transmitted
    pub data: &'a [IoSlice<'a>],
    /// Output result. The number of bytes sent by `batch_send`
    pub data_len: usize,
}

/// Message struct for `batch_recv`
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd"
))]
pub struct BatchRecvMessage<'a> {
    /// Peer address
    pub addr: SocketAddr,
    /// Data buffer for receiving
    pub data: &'a mut [IoSliceMut<'a>],
    /// Output result. The number of bytes received by `batch_recv`
    pub data_len: usize,
}

#[inline]
fn make_mtu_error(packet_size: usize, mtu: usize) -> io::Error {
    io::Error::other(format!("UDP packet {} > MTU {}", packet_size, mtu))
}

/// Wrappers for outbound `UdpSocket`
#[derive(Debug)]
pub struct UdpSocket {
    socket: tokio::net::UdpSocket,
    mtu: Option<usize>,
}

impl UdpSocket {
    /// Connects to shadowsocks server
    pub async fn connect_server_with_opts(
        context: &Context,
        addr: &ServerAddr,
        opts: &ConnectOpts,
    ) -> io::Result<Self> {
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

        Ok(Self {
            socket,
            mtu: opts.udp.mtu,
        })
    }

    /// Connects to proxy target
    pub async fn connect_remote_with_opts(context: &Context, addr: &Address, opts: &ConnectOpts) -> io::Result<Self> {
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

        Ok(Self {
            socket,
            mtu: opts.udp.mtu,
        })
    }

    /// Connects to shadowsocks server
    pub async fn connect_with_opts(addr: &SocketAddr, opts: &ConnectOpts) -> io::Result<Self> {
        let socket = create_outbound_udp_socket(From::from(addr), opts).await?;
        socket.connect(addr).await?;
        Ok(Self {
            socket,
            mtu: opts.udp.mtu,
        })
    }

    /// Binds to a specific address with opts
    pub async fn connect_any_with_opts<AF: Into<AddrFamily>>(af: AF, opts: &ConnectOpts) -> io::Result<Self> {
        create_outbound_udp_socket(af.into(), opts).await.map(|socket| Self {
            socket,
            mtu: opts.udp.mtu,
        })
    }

    /// Binds to a specific address as an outbound socket
    #[inline]
    pub async fn bind(addr: &SocketAddr) -> io::Result<Self> {
        Self::bind_with_opts(addr, &ConnectOpts::default()).await
    }

    /// Binds to a specific address with opts as an outbound socket
    pub async fn bind_with_opts(addr: &SocketAddr, opts: &ConnectOpts) -> io::Result<Self> {
        bind_outbound_udp_socket(addr, opts).await.map(|socket| Self {
            socket,
            mtu: opts.udp.mtu,
        })
    }

    /// Binds to a specific address (inbound)
    #[inline]
    pub async fn listen(addr: &SocketAddr) -> io::Result<Self> {
        Self::listen_with_opts(addr, AcceptOpts::default()).await
    }

    /// Binds to a specific address (inbound)
    pub async fn listen_with_opts(addr: &SocketAddr, opts: AcceptOpts) -> io::Result<Self> {
        let socket = create_inbound_udp_socket(addr, opts.ipv6_only).await?;
        Ok(Self {
            socket,
            mtu: opts.udp.mtu,
        })
    }

    /// Wrapper of `UdpSocket::poll_send`
    pub fn poll_send(&self, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Check MTU
        if let Some(mtu) = self.mtu {
            if buf.len() > mtu {
                return Err(make_mtu_error(buf.len(), mtu)).into();
            }
        }

        self.socket.poll_send(cx, buf)
    }

    /// Wrapper of `UdpSocket::send`
    #[inline]
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // Check MTU
        if let Some(mtu) = self.mtu {
            if buf.len() > mtu {
                return Err(make_mtu_error(buf.len(), mtu));
            }
        }

        self.socket.send(buf).await
    }

    /// Wrapper of `UdpSocket::poll_send_to`
    pub fn poll_send_to(&self, cx: &mut TaskContext<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>> {
        // Check MTU
        if let Some(mtu) = self.mtu {
            if buf.len() > mtu {
                return Err(make_mtu_error(buf.len(), mtu)).into();
            }
        }

        self.socket.poll_send_to(cx, buf, target)
    }

    /// Wrapper of `UdpSocket::send_to`
    #[inline]
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
        // Check MTU
        if let Some(mtu) = self.mtu {
            if buf.len() > mtu {
                return Err(make_mtu_error(buf.len(), mtu));
            }
        }

        self.socket.send_to(buf, target).await
    }

    /// Wrapper of `UdpSocket::poll_recv`
    #[inline]
    pub fn poll_recv(&self, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        ready!(self.socket.poll_recv(cx, buf))?;

        if let Some(mtu) = self.mtu {
            if buf.filled().len() > mtu {
                return Err(make_mtu_error(buf.filled().len(), mtu)).into();
            }
        }

        Ok(()).into()
    }

    /// Wrapper of `UdpSocket::recv`
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.socket.recv(buf).await?;

        if let Some(mtu) = self.mtu {
            if n > mtu {
                return Err(make_mtu_error(n, mtu));
            }
        }

        Ok(n)
    }

    /// Wrapper of `UdpSocket::poll_recv_from`
    #[inline]
    pub fn poll_recv_from(&self, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<SocketAddr>> {
        let addr = ready!(self.socket.poll_recv_from(cx, buf))?;

        if let Some(mtu) = self.mtu {
            if buf.filled().len() > mtu {
                return Err(make_mtu_error(buf.filled().len(), mtu)).into();
            }
        }

        Ok(addr).into()
    }

    /// Wrapper of `UdpSocket::recv`
    #[inline]
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, addr) = self.socket.recv_from(buf).await?;

        if let Some(mtu) = self.mtu {
            if n > mtu {
                return Err(make_mtu_error(n, mtu));
            }
        }

        Ok((n, addr))
    }

    /// Batch send packets
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    ))]
    pub fn poll_batch_send(
        &self,
        cx: &mut TaskContext<'_>,
        msgs: &mut [BatchSendMessage<'_>],
    ) -> Poll<io::Result<usize>> {
        use super::sys::batch_sendmsg;

        loop {
            ready!(self.socket.poll_send_ready(cx))?;

            match self
                .socket
                .try_io(Interest::WRITABLE, || batch_sendmsg(&self.socket, msgs))
            {
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
        target_os = "ios",
        target_os = "freebsd"
    ))]
    pub async fn batch_send(&self, msgs: &mut [BatchSendMessage<'_>]) -> io::Result<usize> {
        future::poll_fn(|cx| self.poll_batch_send(cx, msgs)).await
    }

    /// Batch recv packets
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "ios",
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
            ready!(self.socket.poll_recv_ready(cx))?;

            match self
                .socket
                .try_io(Interest::READABLE, || batch_recvmsg(&self.socket, msgs))
            {
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
        target_os = "ios",
        target_os = "freebsd"
    ))]
    pub async fn batch_recv(&self, msgs: &mut [BatchRecvMessage<'_>]) -> io::Result<usize> {
        future::poll_fn(|cx| self.poll_batch_recv(cx, msgs)).await
    }
}

impl Deref for UdpSocket {
    type Target = tokio::net::UdpSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for UdpSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl From<tokio::net::UdpSocket> for UdpSocket {
    fn from(socket: tokio::net::UdpSocket) -> Self {
        Self { socket, mtu: None }
    }
}

impl From<UdpSocket> for tokio::net::UdpSocket {
    fn from(s: UdpSocket) -> Self {
        s.socket
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket.as_raw_fd()
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for UdpSocket {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        self.socket.as_raw_socket()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for UdpSocket {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.socket.as_socket()
    }
}
