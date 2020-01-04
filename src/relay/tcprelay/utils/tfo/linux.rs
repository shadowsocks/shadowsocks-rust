//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{self, SocketAddr},
    os::unix::io::AsRawFd,
};

use libc;
use log::error;
use tokio::net::{TcpListener, TcpStream};

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

        // TCP_FASTOPEN was supported since Linux 3.7

        let queue_size: libc::c_int = 5;

        let ret = libc::setsockopt(
            sockfd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &queue_size as *const _ as *const libc::c_void,
            mem::size_of_val(&queue_size) as libc::socklen_t,
        );

        if ret != 0 {
            error!(
                "Failed to listen on {} with TFO enabled, supported after Linux 3.7",
                addr
            );

            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        TcpListener::from_std(net::TcpListener::from_raw_fd(sockfd))
    }
}

pub async fn connect_stream(addr: &SocketAddr) -> io::Result<TcpStream> {
    let domain = match addr {
        SocketAddr::V4(..) => libc::AF_INET,
        SocketAddr::V6(..) => libc::AF_INET6,
    };

    let sockfd = create_socket(domain)?;

    unsafe {
        // TCP_FASTOPEN was supported since Linux 3.7

        let (saddr, saddr_len) = addr2raw(addr);

        // After 4.11, Linux has a new option TCP_FASTOPEN_CONNECT
        // Set it before connect

        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            sockfd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret == -1 {
            let errno = *libc::__errno_location();

            if errno == libc::ENOPROTOOPT {
                // TCP_FASTOPEN_CONNECT is not supported, maybe kernel version < 4.11
                // Ignore it

                // FIXME: Fallback to `sendto` with `MSG_FASTOPEN`

                let empty_buf: [u8; 0] = [];

                let ret = libc::sendto(
                    sockfd,
                    empty_buf.as_ptr() as *const libc::c_void,
                    0,
                    libc::MSG_FASTOPEN,
                    saddr,
                    saddr_len,
                );
                if ret < 0 {
                    let errno = *libc::__errno_location();

                    if errno == libc::EOPNOTSUPP {
                        error!(
                            "Failed to connect to {} with TFO enabled, supported after Linux 3.7",
                            addr
                        );
                    }

                    let _ = libc::close(sockfd);
                    return Err(Error::from_raw_os_error(errno));
                }
            } else {
                let _ = libc::close(sockfd);
                return Err(Error::from_raw_os_error(errno));
            }
        } else {
            // Call connect as normal
            let ret = libc::connect(sockfd, saddr, saddr_len);
            if ret == -1 {
                let _ = libc::close(sockfd);
                return Err(Error::last_os_error());
            }
        }

        TcpStream::from_std(net::TcpStream::from_raw_fd(sockfd))
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
