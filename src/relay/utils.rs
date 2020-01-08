use std::{
    future::Future,
    io::{self, Error},
    mem,
    net::SocketAddr,
    time::Duration,
};

use tokio::time;
#[cfg(windows)]
use winapi::{
    ctypes,
    shared::ws2def::SOCKADDR,
    um::winsock2::{bind, closesocket, ioctlsocket, socket, WSAGetLastError, FIONBIO, INVALID_SOCKET, SOCKET},
};

pub async fn try_timeout<T, E, F>(fut: F, timeout: Option<Duration>) -> io::Result<T>
where
    F: Future<Output = Result<T, E>>,
    Error: From<E>,
{
    match timeout {
        Some(t) => time::timeout(t, fut).await?,
        None => fut.await,
    }
    .map_err(From::from)
}

#[cfg(unix)]
pub fn addr2raw(addr: &SocketAddr) -> (*const libc::sockaddr, libc::socklen_t) {
    match *addr {
        SocketAddr::V4(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t),
        SocketAddr::V6(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t),
    }
}

#[cfg(windows)]
pub fn addr2raw(addr: &SocketAddr) -> (*const SOCKADDR, ctypes::c_int) {
    match *addr {
        SocketAddr::V4(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as ctypes::c_int),
        SocketAddr::V6(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as ctypes::c_int),
    }
}

/// Create a new socket with O_NONBLOCK flag set
///
/// Borrowed from mio: src/sys/unix/net.rs
#[cfg(unix)]
pub fn create_socket_nonblock(domain: libc::c_int, socket_type: libc::c_int) -> io::Result<libc::c_int> {
    unsafe {
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        let socket_type = socket_type | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;

        // Gives a warning for platforms without SOCK_NONBLOCK.
        #[allow(clippy::let_and_return)]
        let socket = libc::socket(domain, socket_type, 0);
        if socket < 0 {
            return Err(Error::last_os_error());
        }
        // Darwin doesn't have SOCK_NONBLOCK or SOCK_CLOEXEC. Not sure about Solaris, couldn't find anything online.
        if cfg!(any(target_os = "ios", target_os = "macos", target_os = "solaris")) {
            // For platforms that don't support flags in socket, we need to set the flags ourselves.
            let ret = libc::fcntl(
                socket,
                libc::F_SETFL,
                libc::fcntl(socket, libc::F_GETFL) | libc::O_NONBLOCK,
            );

            if ret == -1 {
                let err = Error::last_os_error();
                libc::close(socket);
                return Err(err);
            }

            let ret = libc::fcntl(
                socket,
                libc::F_SETFD,
                libc::fcntl(socket, libc::F_GETFD) | libc::FD_CLOEXEC,
            );

            if ret == -1 {
                let err = Error::last_os_error();
                libc::close(socket);
                return Err(err);
            }
        }

        Ok(socket)
    }
}

/// Create a new socket with FIONBIO flag set
///
/// Borrowed from mio: src/sys/windows/net.rs
#[cfg(windows)]
pub fn create_socket_nonblock(address_family: ctypes::c_int, socket_type: ctypes::c_int) -> io::Result<SOCKET> {
    let handle = socket(address_family, socket_type);
    if handle == INVALID_SOCKET {
        return Err(Error::from_raw_os_error(WSAGetLastError()));
    }

    let ret = ioctlsocket(handle, FIONBIO, &mut 1);
    if ret != 0 {
        return Err(Error::from_raw_os_error(WSAGetLastError()));
    }

    Ok(handle)
}

/// Bind a socket with addr
#[cfg(unix)]
pub fn bind_socket(socket: libc::c_int, addr: &SocketAddr) -> io::Result<()> {
    unsafe {
        let (saddr, saddr_len) = addr2raw(addr);
        if libc::bind(socket, saddr, saddr_len) != 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

/// Bind a socket with addr
#[cfg(windows)]
pub fn bind_socket(socket: SOCKET, addr: &SocketAddr) -> io::Result<()> {
    unsafe {
        let (saddr, saddr_len) = addr2raw(addr);
        if bind(socket, saddr, saddr_len) != 0 {
            return Err(Error::from_raw_os_error(WSAGetLastError()));
        }
        Ok(())
    }
}

#[cfg(unix)]
pub fn close_socket(socket: libc::c_int) -> io::Result<()> {
    unsafe {
        if libc::close(socket) != 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
pub fn close_socket(socket: SOCKET) -> io::Result<()> {
    unsafe {
        if closesocket(socket) != 0 {
            Err(Error::from_raw_os_error(WSAGetLastError()))
        } else {
            Ok(())
        }
    }
}
