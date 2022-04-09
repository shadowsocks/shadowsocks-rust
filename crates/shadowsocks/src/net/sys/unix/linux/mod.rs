use std::{
    io,
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    task::{self, Poll},
};

use cfg_if::cfg_if;
use log::{error, warn};
use pin_project::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};
use tokio_tfo::TfoStream;

use crate::net::{
    sys::{set_common_sockopt_after_connect, set_common_sockopt_for_connect},
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

        // Any traffic to localhost should not be protected
        // This is a workaround for VPNService
        #[cfg(target_os = "android")]
        if !addr.ip().is_loopback() {
            use std::{io::ErrorKind, time::Duration};
            use tokio::time;

            if let Some(ref path) = opts.vpn_protect_path {
                // RPC calls to `VpnService.protect()`
                // Timeout in 3 seconds like shadowsocks-libev
                match time::timeout(Duration::from_secs(3), vpn_protect(path, socket.as_raw_fd())).await {
                    Ok(Ok(..)) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(..) => return Err(io::Error::new(ErrorKind::TimedOut, "protect() timeout")),
                }
            }
        }

        // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
        // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
        if let Some(mark) = opts.fwmark {
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const _ as *const _,
                    mem::size_of_val(&mark) as libc::socklen_t,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                error!("set SO_MARK error: {}", err);
                return Err(err);
            }
        }

        // Set SO_BINDTODEVICE for binding to a specific interface
        if let Some(ref iface) = opts.bind_interface {
            set_bindtodevice(&socket, iface)?;
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
/// `TCP_FASTOPEN` was supported since Linux 3.7
pub fn set_tcp_fastopen<S: AsRawFd>(socket: &S) -> io::Result<()> {
    // https://lwn.net/Articles/508865/
    //
    // The option value, qlen, specifies this server's limit on the size of the queue of TFO requests that have
    // not yet completed the three-way handshake (see the remarks on prevention of resource-exhaustion attacks above).
    //
    // It was recommended to be `5` in this document.
    //
    // But since mio's TcpListener sets backlogs to 1024, it would be nice to have 1024 slots for handshaking TFO requests.
    let queue: libc::c_int = 1024;

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &queue as *const _ as *const libc::c_void,
            mem::size_of_val(&queue) as libc::socklen_t,
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
    // For Linux, IP_MTU_DISCOVER should be enabled for both IPv4 and IPv6 sockets
    // https://man7.org/linux/man-pages/man7/ip.7.html

    unsafe {
        let value: i32 = libc::IP_PMTUDISC_DO;
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &value as *const _ as *const _,
            mem::size_of_val(&value) as libc::socklen_t,
        );

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if af == AddrFamily::Ipv6 {
            let value: i32 = libc::IP_PMTUDISC_DO;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &value as *const _ as *const _,
                mem::size_of_val(&value) as libc::socklen_t,
            );

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

/// Create a `UdpSocket` for connecting to `addr`
pub async fn create_outbound_udp_socket(af: AddrFamily, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, config.bind_local_addr) {
        (AddrFamily::Ipv4, Some(IpAddr::V4(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv6, Some(IpAddr::V6(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv4, ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (AddrFamily::Ipv6, ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    if let Err(err) = set_disable_ip_fragmentation(af, &socket) {
        warn!("failed to disable IP fragmentation, error: {}", err);
    }

    // Any traffic except localhost should be protected
    // This is a workaround for VPNService
    #[cfg(target_os = "android")]
    {
        use std::{io::ErrorKind, time::Duration};
        use tokio::time;

        if let Some(ref path) = config.vpn_protect_path {
            // RPC calls to `VpnService.protect()`
            // Timeout in 3 seconds like shadowsocks-libev
            match time::timeout(Duration::from_secs(3), vpn_protect(path, socket.as_raw_fd())).await {
                Ok(Ok(..)) => {}
                Ok(Err(err)) => return Err(err),
                Err(..) => return Err(io::Error::new(ErrorKind::TimedOut, "protect() timeout")),
            }
        }
    }

    // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
    // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
    if let Some(mark) = config.fwmark {
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const _,
                mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_MARK error: {}", err);
            return Err(err);
        }
    }

    // Set SO_BINDTODEVICE for binding to a specific interface
    if let Some(ref iface) = config.bind_interface {
        set_bindtodevice(&socket, iface)?;
    }

    Ok(socket)
}

fn set_bindtodevice<S: AsRawFd>(socket: &S, iface: &str) -> io::Result<()> {
    let iface_bytes = iface.as_bytes();

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_bytes.as_ptr() as *const _ as *const libc::c_void,
            iface_bytes.len() as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_BINDTODEVICE error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

cfg_if! {
    if #[cfg(target_os = "android")] {
        use std::{
            io::ErrorKind,
            path::Path,
        };
        use tokio::io::AsyncReadExt;

        use super::uds::UnixStream;

        /// This is a RPC for Android to `protect()` socket for connecting to remote servers
        ///
        /// https://developer.android.com/reference/android/net/VpnService#protect(java.net.Socket)
        ///
        /// More detail could be found in [shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android) project.
        async fn vpn_protect<P: AsRef<Path>>(protect_path: P, fd: RawFd) -> io::Result<()> {
            let mut stream = UnixStream::connect(protect_path).await?;

            // send fds
            let dummy: [u8; 1] = [1];
            let fds: [RawFd; 1] = [fd];
            stream.send_with_fd(&dummy, &fds).await?;

            // receive the return value
            let mut response = [0; 1];
            stream.read_exact(&mut response).await?;

            if response[0] == 0xFF {
                return Err(io::Error::new(ErrorKind::Other, "protect() failed"));
            }

            Ok(())
        }
    }
}
