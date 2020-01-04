//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    os::unix::io::AsRawFd,
};

use libc;
use log::error;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};

fn create_socket(domain: libc::c_int) -> io::Result<libc::c_int> {
    unsafe {
        let sockfd = libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if sockfd == -1 {
            return Err(Error::last_os_error());
        }

        Ok(sockfd)
    }
}

pub async fn bind_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(..) => libc::AF_INET,
        SocketAddr::V6(..) => libc::AF_INET6,
    };

    let sockfd = create_socket(domain)?;

    unsafe {
        // Set SO_REUSEADDR (mirrors what libstd does).
        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            sockfd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret == -1 {
            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        // bind & listen
        // NOTE: Must call before setting TCP_FASTOPEN
        let (saddr, saddr_len) = addr2raw(addr);
        let ret = libc::bind(sockfd, saddr, saddr_len);
        if ret == -1 {
            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        let ret = libc::listen(sockfd, 1024 /* Set just like libstd and mio does */);
        if ret == -1 {
            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        // TCP_FASTOPEN was supported since FreeBSD 12.0
        //
        // Example program:
        // https://people.freebsd.org/~pkelsey/tfo-tools/tfo-srv.c

        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            sockfd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            error!(
                "Failed to listen on {} with TFO enabled, supported after FreeBSD 12.0, ...",
                addr
            );

            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        TcpListener::from_std(StdTcpListener::from_raw_fd(sockfd))
    }
}

pub struct ConnectContext {
    // Reference to the partial connected socket fd
    // This struct doesn't own the fd, so do not close it while dropping
    socket: RawFd,

    // Target address for calling `sendto`
    remote_addr: SocketAddr,
}

impl ConnectContext {
    /// Performing actual connect operation
    pub fn connect_with_data(self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let (saddr, saddr_len) = addr2raw(&self.remote_addr);

            let ret = libc::sendto(
                self.socket,
                buf.as_ptr() as *const _ as *const libc::c_void,
                buf.len(),
                0,
                saddr,
                saddr_len,
            );

            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }
    }
}

pub async fn connect_stream(addr: &SocketAddr) -> io::Result<(TcpStream, ConnectContext)> {
    let domain = match addr {
        SocketAddr::V4(..) => libc::AF_INET,
        SocketAddr::V6(..) => libc::AF_INET6,
    };

    let sockfd = create_socket(domain)?;

    unsafe {
        // TCP_FASTOPEN was supported since FreeBSD 12.0
        //
        // Example program:
        // https://people.freebsd.org/~pkelsey/tfo-tools/tfo-client.c

        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            sockfd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            error!(
                "Failed to connect to {} with TFO enabled, supported after FreeBSD 12.0, ...",
                addr
            );

            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        let (saddr, saddr_len) = addr2raw(addr);

        let empty_buf: [u8; 0] = [];

        let ret = libc::sendto(
            sockfd,
            empty_buf.as_ptr() as *const libc::c_void,
            0,
            0, // Yes, FreeBSD doesn't need MSG_FASTOPEN
            saddr,
            saddr_len,
        );

        if ret != 0 {
            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        TcpStream::from_std(StdTcpStream::from_raw_fd(sockfd)).map(|s| {
            (
                s,
                ConnectContext {
                    socket: sockfd,
                    remote_addr: *addr,
                },
            )
        })
    }
}

// Borrowed from net2
fn addr2raw(addr: &SocketAddr) -> (*const libc::sockaddr, libc::socklen_t) {
    use std::mem;

    match *addr {
        SocketAddr::V4(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t),
        SocketAddr::V6(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t),
    }
}
