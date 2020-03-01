use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::{AsRawFd, RawFd},
};

use socket2::{Domain, Protocol, Socket, Type};

use tokio::net::{TcpStream, UdpSocket};

#[cfg(all(feature = "sendfd", target_os = "android"))]
use sendfd::*;
#[cfg(all(feature = "sendfd", target_os = "android"))]
use std::{io::prelude::*, os::unix::net::UnixStream, time::Duration};

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

#[cfg(target_os = "android")]
fn protect(protect_path: &Option<String>, fd: RawFd) -> io::Result<()> {
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

#[cfg(not(target_os = "android"))]
fn protect(_protect_path: &Option<String>, _fd: RawFd) -> io::Result<()> {
    Ok(())
}

/// create a new TCP stream
#[inline(always)]
pub async fn tcp_stream_connect(saddr: &SocketAddr, context: &Context) -> io::Result<TcpStream> {
    let domain = match *saddr {
        SocketAddr::V4(..) => Domain::ipv4(),
        SocketAddr::V6(..) => Domain::ipv6(),
    };

    let socket = Socket::new(domain, Type::stream(), Some(Protocol::tcp()))?;

    // Any traffic to localhost should be protected
    // This is a workaround for VPNService
    if cfg!(target_os = "android") {
        if saddr.ip() != IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) {
            protect(&context.config().protect_path, socket.as_raw_fd())?;
        }
    }

    let stream = socket.into_tcp_stream();
    TcpStream::connect_std(stream, &saddr).await
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket_with_context(addr: &SocketAddr, context: &Context) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;

    // Any traffic to localhost should be protected
    // This is a workaround for VPNService
    if cfg!(target_os = "android") {
        if addr.ip() != IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)) {
            protect(&context.config().protect_path, socket.as_raw_fd())?;
        }
    }

    Ok(socket)
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}
