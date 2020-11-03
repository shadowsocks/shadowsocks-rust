use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::{AsRawFd, RawFd},
    path::Path,
};

use cfg_if::cfg_if;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpStream, UdpSocket};

use crate::context::Context;

/// Convert `sockaddr_storage` to `SocketAddr`
#[allow(dead_code)]
pub fn sockaddr_to_std(saddr: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match saddr.ss_family as libc::c_int {
        libc::AF_INET => unsafe {
            let addr: SocketAddrV4 = mem::transmute_copy(saddr);
            Ok(SocketAddr::V4(addr))
        },
        libc::AF_INET6 => unsafe {
            let addr: SocketAddrV6 = mem::transmute_copy(saddr);
            Ok(SocketAddr::V6(addr))
        },
        _ => {
            let err = Error::new(ErrorKind::InvalidData, "family must be either AF_INET or AF_INET6");
            Err(err)
        }
    }
}

cfg_if! {
    if #[cfg(target_os = "android")] {
        mod uds;

        /// This is a RPC for Android to `protect()` socket for connecting to remote servers
        ///
        /// https://developer.android.com/reference/android/net/VpnService#protect(java.net.Socket)
        ///
        /// More detail could be found in [shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android) project.
        async fn protect<P: AsRef<Path>>(protect_path: P, fd: RawFd) -> io::Result<()> {
            use tokio::io::AsyncReadExt;

            let mut stream = self::uds::UnixStream::connect(protect_path).await?;

            // send fds
            let dummy: [u8; 1] = [1];
            let fds: [RawFd; 1] = [fd];
            stream.send_with_fd(&dummy, &fds).await?;

            // receive the return value
            let mut response = [0; 1];
            stream.read_exact(&mut response).await?;

            if response[0] == 0xFF {
                return Err(Error::new(ErrorKind::Other, "protect() failed"));
            }

            Ok(())
        }
    } else {
        #[inline(always)]
        async fn protect<P: AsRef<Path>>(_protect_path: P, _fd: RawFd) -> io::Result<()> {
            Ok(())
        }
    }
}

/// create a new TCP stream
#[inline(always)]
pub async fn tcp_stream_connect(saddr: &SocketAddr, context: &Context) -> io::Result<TcpStream> {
    let domain = match *saddr {
        SocketAddr::V4(..) => Domain::ipv4(),
        SocketAddr::V6(..) => Domain::ipv6(),
    };

    let socket = Socket::new(domain, Type::stream(), Some(Protocol::tcp()))?;
    socket.set_nonblocking(true)?;

    // Any traffic to localhost should not be protected
    // This is a workaround for VPNService
    if cfg!(target_os = "android") && !saddr.ip().is_loopback() {
        if let Some(ref path) = context.config().protect_path {
            protect(path, socket.as_raw_fd()).await?;
        }
    }

    // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
    // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(mark) = context.config().outbound_fwmark {
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
            return Err(Error::last_os_error());
        }
    }

    // it's important that the socket is protected before connecting
    let stream = socket.into_tcp_stream();
    TcpStream::connect_std(stream, &saddr).await
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket_with_context(addr: &SocketAddr, context: &Context) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;

    // Any traffic to localhost should be protected
    // This is a workaround for VPNService
    if cfg!(target_os = "android") && !addr.ip().is_loopback() {
        if let Some(ref path) = context.config().protect_path {
            protect(path, socket.as_raw_fd()).await?;
        }
    }

    Ok(socket)
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}
