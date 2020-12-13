#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::io::AsRawFd;
use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
};
#[cfg(any(target_os = "android"))]
use std::{os::unix::io::RawFd, path::Path};

use cfg_if::cfg_if;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::net::ConnectOpts;

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
    }
}

/// create a new TCP stream
#[inline(always)]
#[allow(unused_variables)]
pub async fn tcp_stream_connect(saddr: &SocketAddr, config: &ConnectOpts) -> io::Result<TcpStream> {
    let socket = match *saddr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    // Any traffic to localhost should not be protected
    // This is a workaround for VPNService
    #[cfg(target_os = "android")]
    if !saddr.ip().is_loopback() {
        if let Some(ref path) = config.vpn_protect_path {
            protect(path, socket.as_raw_fd()).await?;
        }
    }

    // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
    // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
    #[cfg(any(target_os = "linux", target_os = "android"))]
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
            return Err(Error::last_os_error());
        }
    }

    // it's important that the socket is protected before connecting
    socket.connect(*saddr).await
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
#[allow(unused_variables)]
pub async fn create_outbound_udp_socket(addr: &SocketAddr, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;

    // Any traffic to localhost should be protected
    // This is a workaround for VPNService
    #[cfg(target_os = "android")]
    if !addr.ip().is_loopback() {
        if let Some(ref path) = config.vpn_protect_path {
            protect(path, socket.as_raw_fd()).await?;
        }
    }

    // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
    // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
    #[cfg(any(target_os = "linux", target_os = "android"))]
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
            return Err(Error::last_os_error());
        }
    }

    Ok(socket)
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}
