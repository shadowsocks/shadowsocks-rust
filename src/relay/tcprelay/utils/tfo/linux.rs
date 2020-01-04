//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    os::unix::io::{FromRawFd, RawFd},
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

pub async fn bind_listener(addr: &SocketAddr) -> io::Result<TokioTcpListener> {
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

        TokioTcpListener::from_std(StdTcpListener::from_raw_fd(sockfd))
    }
}

pub struct ConnectContext {
    // Reference to the partial connected socket fd
    // This struct doesn't own the fd, so do not close it while dropping
    socket: RawFd,

    // Target address
    // For Linux Kernal >= 4.11, TCP_FASTOPEN_CONNECT doesn't need to call sendto with remote_addr
    // Just call send as normal connection
    remote_addr: Option<SocketAddr>,
}

impl ConnectContext {
    /// Performing actual connect operation
    pub fn connect_with_data(self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            match self.remote_addr {
                Some(addr) => {
                    // Kernal < 4.11, uses `sendto` as BSD-like systems
                    // But flags should be `MSG_FASTOPEN`

                    let (saddr, saddr_len) = addr2raw(&addr);

                    let ret = libc::sendto(
                        self.socket,
                        buf.as_ptr() as *const _ as *const libc::c_void,
                        buf.len(),
                        libc::MSG_FASTOPEN,
                        saddr,
                        saddr_len,
                    );

                    if ret < 0 {
                        let err = Error::last_os_error();
                        match err.raw_os_error() {
                            Some(libc::EOPNOTSUPP) => {
                                // `sendto` with flag `MSG_FASTOPEN` is not supported

                                error!("Failed to connect {} with TFO enabled, supported after Linux 3.7", addr);
                            }
                            _ => {}
                        }
                        Err(err)
                    } else {
                        Ok(ret as usize)
                    }
                }
                None => {
                    // Kernal >= 4.11, already connected with `TCP_FASTOPEN_CONNECT`
                    // Just call send directly

                    let ret = libc::send(
                        self.socket,
                        buf.as_ptr() as *const _ as *const libc::c_void,
                        buf.len(),
                        0, // no flags
                    );
                    if ret < 0 {
                        Err(Error::last_os_error())
                    } else {
                        Ok(ret as usize)
                    }
                }
            }
        }
    }
}

pub async fn connect_stream(addr: &SocketAddr) -> io::Result<(TokioTcpStream, ConnectContext)> {
    let domain = match addr {
        SocketAddr::V4(..) => libc::AF_INET,
        SocketAddr::V6(..) => libc::AF_INET6,
    };

    let sockfd = create_socket(domain)?;

    unsafe {
        // TCP_FASTOPEN was supported since Linux 3.7

        // After 4.11, Linux has a new option `TCP_FASTOPEN_CONNECT`
        // Set it before connect

        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            sockfd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN_CONNECT,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        let remote_addr = if ret == -1 {
            let err = Error::last_os_error();

            match err.raw_os_error() {
                Some(libc::ENOPROTOOPT) => {
                    // `TCP_FASTOPEN_CONNECT` is not supported, maybe kernel version < 4.11
                    // Fallback to `sendto` with `MSG_FASTOPEN` (Supported after 3.7)

                    Some(*addr)
                }
                _ => {
                    let _ = libc::close(sockfd);
                    return Err(err);
                }
            }
        } else {
            let (saddr, saddr_len) = addr2raw(addr);

            // Call connect as normal
            let ret = libc::connect(sockfd, saddr, saddr_len);
            if ret == -1 {
                let err = Error::last_os_error();
                let _ = libc::close(sockfd);
                return Err(err);
            }

            None
        };

        TokioTcpStream::from_std(StdTcpStream::from_raw_fd(sockfd)).map(|s| {
            (
                s,
                ConnectContext {
                    socket: sockfd,
                    remote_addr,
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
