//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{self, IpAddr, SocketAddr},
    os::unix::io::AsRawFd,
};

use libc;
use log::error;
use net2::TcpBuilder;
use tokio::net::{TcpListener, TcpStream};

pub async fn bind_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let listener = net::TcpListener::bind(addr)?;

    let fd = listener.as_raw_fd();

    unsafe {
        // TCP_FASTOPEN was supported since Linux 3.7

        let queue_size: libc::c_int = 5;

        let ret = libc::setsockopt(
            fd,
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

            return Err(Error::last_os_error());
        }
    }

    TcpListener::from_std(listener)
}

pub async fn connect_stream(addr: &SocketAddr) -> io::Result<TcpStream> {
    let builder = match addr.ip() {
        IpAddr::V4(..) => TcpBuilder::new_v4()?,
        IpAddr::V6(..) => TcpBuilder::new_v6()?,
    };

    // Build it first, to retrive the socket fd
    let stream = builder.to_tcp_stream()?;
    let sockfd = stream.as_raw_fd();

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

        if ret != 0 {
            let errno = *libc::__errno_location();

            if errno == libc::ENOPROTOOPT {
                // TCP_FASTOPEN_CONNECT is not supported, maybe kernel version < 4.11
                // Ignoure it

                // Fallback to `sendto` with `MSG_FASTOPEN`

                let empty_buf: [u8; 0] = [];

                let ret = libc::sendto(
                    sockfd,
                    empty_buf.as_ptr() as *const libc::c_void,
                    0,
                    libc::MSG_FASTOPEN,
                    saddr,
                    saddr_len,
                );
                if ret != 0 {
                    let errno = *libc::__errno_location();

                    if errno == libc::EOPNOTSUPP {
                        error!(
                            "Failed to connect to {} with TFO enabled, supported after Linux 3.7",
                            addr
                        );
                    }

                    return Err(Error::from_raw_os_error(errno));
                }
            } else {
                return Err(Error::from_raw_os_error(errno));
            }
        } else {
            // Call connect as normal
            let ret = libc::connect(sockfd, saddr, saddr_len);
            if ret != 0 {
                let errno = *libc::__errno_location();
                return Err(Error::from_raw_os_error(errno));
            }
        }
    }

    TcpStream::from_std(stream)
}

// Borrowed from net2
fn addr2raw(addr: &SocketAddr) -> (*const libc::sockaddr, libc::socklen_t) {
    use std::mem;

    match *addr {
        SocketAddr::V4(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t),
        SocketAddr::V6(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t),
    }
}
