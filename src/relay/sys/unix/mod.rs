use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::{AsRawFd, RawFd},
};

use cfg_if::cfg_if;
use tokio::net::{TcpStream, UdpSocket};

use crate::context::Context;

cfg_if! {
    if #[cfg(any(target_os = "macos",
                 target_os = "ios",
                 target_os = "freebsd",
                 target_os = "netbsd",
                 target_os = "openbsd"))] {
        pub mod bsd_pf;
    }
}

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
        /// This is a RPC for Android to `protect()` socket for connecting to remote servers
        ///
        /// https://developer.android.com/reference/android/net/VpnService#protect(java.net.Socket)
        ///
        /// More detail could be found in [shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android) project.
        fn protect(protect_path: &Option<String>, fd: RawFd) -> io::Result<()> {
            use std::{io::Read, os::unix::net::UnixStream, time::Duration};

            use sendfd::{RecvWithFd, SendWithFd};

            // ignore if protect_path is not specified
            let path = match protect_path {
                Some(path) => path,
                None => return Ok(()),
            };

            // it's safe to use blocking socket here
            let mut stream = UnixStream::connect(path)?;
            stream
                .set_read_timeout(Some(Duration::new(1, 0)))
                .expect("couldn't set read timeout");
            stream
                .set_write_timeout(Some(Duration::new(1, 0)))
                .expect("couldn't set write timeout");

            // send fds
            let dummy: [u8; 1] = [1];
            let fds: [RawFd; 1] = [fd];
            stream.send_with_fd(&dummy, &fds)?;

            // receive the return value
            let mut response = [0; 1];
            stream.read(&mut response)?;
            if response[0] == 0xFF {
                return Err(Error::new(ErrorKind::Other, "protect() failed"));
            }

            Ok(())
        }
    } else {
        #[inline(always)]
        fn protect(_protect_path: &Option<String>, _fd: RawFd) -> io::Result<()> {
            Ok(())
        }
    }
}

/// create a new TCP stream
#[inline(always)]
pub async fn tcp_stream_connect(saddr: &SocketAddr, context: &Context) -> io::Result<TcpStream> {
    let stream = TcpStream::connect(saddr).await?;

    // Any traffic to localhost should be protected
    // This is a workaround for VPNService
    if cfg!(target_os = "android") && !saddr.ip().is_loopback() {
        protect(&context.config().protect_path, stream.as_raw_fd())?;
    }

    Ok(stream)
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket_with_context(addr: &SocketAddr, context: &Context) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;

    // Any traffic to localhost should be protected
    // This is a workaround for VPNService
    if cfg!(target_os = "android") && !addr.ip().is_loopback() {
        protect(&context.config().protect_path, socket.as_raw_fd())?;
    }

    Ok(socket)
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}
