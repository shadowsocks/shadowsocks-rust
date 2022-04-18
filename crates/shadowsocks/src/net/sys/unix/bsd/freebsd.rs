use std::{
    io,
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    task::{self, Poll},
};

use log::{error, warn};
use pin_project::pin_project;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};
use tokio_tfo::TfoStream;

use crate::net::{
    sys::{set_common_sockopt_after_connect, set_common_sockopt_for_connect, socket_bind_dual_stack},
    AddrFamily,
    ConnectOpts,
};

/// A `TcpStream` that supports TFO (TCP Fast Open)
#[pin_project(project = TcpStreamProj)]
pub enum TcpStream {
    Standard(#[pin] TokioTcpStream),
    FastOpen(#[pin] TfoStream),
}

impl TcpStream {
    pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        // Set SO_USER_COOKIE for mark-based routing on FreeBSD
        if let Some(user_cookie) = opts.user_cookie {
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_USER_COOKIE,
                    &user_cookie as *const _ as *const _,
                    mem::size_of_val(&user_cookie) as libc::socklen_t,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                error!("set SO_USER_COOKIE error: {}", err);
                return Err(err);
            }
        }

        set_common_sockopt_for_connect(addr, &socket, opts)?;

        if !opts.tcp.fastopen {
            // If TFO is not enabled, it just works like a normal TcpStream
            let stream = socket.connect(addr).await?;
            set_common_sockopt_after_connect(&stream, opts)?;

            return Ok(TcpStream::Standard(stream));
        }

        let stream = TfoStream::connect_with_socket(socket, addr).await?;
        set_common_sockopt_after_connect(&stream, opts)?;

        Ok(TcpStream::FastOpen(stream))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            TcpStream::Standard(ref s) => s.local_addr(),
            TcpStream::FastOpen(ref s) => s.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            TcpStream::Standard(ref s) => s.peer_addr(),
            TcpStream::FastOpen(ref s) => s.peer_addr(),
        }
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        match *self {
            TcpStream::Standard(ref s) => s.nodelay(),
            TcpStream::FastOpen(ref s) => s.nodelay(),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match *self {
            TcpStream::Standard(ref s) => s.set_nodelay(nodelay),
            TcpStream::FastOpen(ref s) => s.set_nodelay(nodelay),
        }
    }
}

impl AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        match *self {
            TcpStream::Standard(ref s) => s.as_raw_fd(),
            TcpStream::FastOpen(ref s) => s.as_raw_fd(),
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_read(cx, buf),
            TcpStreamProj::FastOpen(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_write(cx, buf),
            TcpStreamProj::FastOpen(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_flush(cx),
            TcpStreamProj::FastOpen(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_shutdown(cx),
            TcpStreamProj::FastOpen(s) => s.poll_shutdown(cx),
        }
    }
}

/// Enable `TCP_FASTOPEN`
///
/// TCP_FASTOPEN was supported since FreeBSD 12.0
///
/// Example program: <https://people.freebsd.org/~pkelsey/tfo-tools/tfo-srv.c>
pub fn set_tcp_fastopen<S: AsRawFd>(socket: &S) -> io::Result<()> {
    let enable: libc::c_int = 1;

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set TCP_FASTOPEN error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

/// Disable IP fragmentation
#[inline]
pub fn set_disable_ip_fragmentation<S: AsRawFd>(af: AddrFamily, socket: &S) -> io::Result<()> {
    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE

    // sys/netinet/in.h
    const IP_DONTFRAG: libc::c_int = 67; // don't fragment packet

    // sys/netinet6/in6.h
    const IPV6_DONTFRAG: libc::c_int = 62; // bool; disable IPv6 fragmentation

    unsafe {
        match af {
            AddrFamily::Ipv4 => {
                let enable: i32 = 1;
                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    IP_DONTFRAG,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                );

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            AddrFamily::Ipv6 => {
                let enable: i32 = 1;
                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    IPV6_DONTFRAG,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                );

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }

    Ok(())
}

/// Create a `UdpSocket` for connecting to `addr`
#[inline(always)]
pub async fn create_outbound_udp_socket(af: AddrFamily, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, config.bind_local_addr) {
        (AddrFamily::Ipv4, Some(IpAddr::V4(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv6, Some(IpAddr::V6(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv4, ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (AddrFamily::Ipv6, ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let socket = if af != AddrFamily::Ipv6 {
        UdpSocket::bind(bind_addr).await?
    } else {
        let socket = Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket_bind_dual_stack(&socket, &bind_addr, false)?;

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())?
    };

    if let Err(err) = set_disable_ip_fragmentation(af, &socket) {
        warn!("failed to disable IP fragmentation, error: {}", err);
    }

    Ok(socket)
}
