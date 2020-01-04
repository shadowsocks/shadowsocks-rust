//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{self, SocketAddr},
    os::unix::io::FromRawFd,
    ptr,
};

use libc;
use log::error;
use tokio::net::{TcpListener, TcpStream};

fn create_socket(domain: libc::c_int) -> io::Result<libc::c_int> {
    unsafe {
        let sockfd = libc::socket(domain, libc::SOCK_STREAM, 0);
        if sockfd == -1 {
            return Err(Error::last_os_error());
        }

        // macOS doesn't have SOCK_NONBLOCK or SOCK_CLOEXEC
        let ret = libc::fcntl(
            sockfd,
            libc::F_SETFL,
            libc::fcntl(sockfd, libc::F_GETFL) | libc::O_NONBLOCK,
        );
        if ret == -1 {
            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        let ret = libc::fcntl(
            sockfd,
            libc::F_SETFD,
            libc::fcntl(sockfd, libc::F_GETFD) | libc::FD_CLOEXEC,
        );
        if ret == -1 {
            let _ = libc::close(sockfd);
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

        // TCP_FASTOPEN was supported since
        // macosx(10.11), ios(9.0), tvos(9.0), watchos(2.0)

        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            sockfd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret == -1 {
            error!("Failed to listen on {} with TFO enabled, supported after Mac OS X 10.11, iOS 9.0, tvOS 9.0, watchOS 2.0", addr);

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
        // TCP_FASTOPEN was supported since
        // macosx(10.11), ios(9.0), tvos(9.0), watchos(2.0)

        let (saddr, saddr_len) = addr2raw(addr);
        let mut endpoints: libc::sa_endpoints_t = mem::zeroed();
        endpoints.sae_dstaddr = saddr;
        endpoints.sae_dstaddrlen = saddr_len;

        let ret = libc::connectx(
            sockfd,
            &endpoints as *const _,
            libc::SAE_ASSOCID_ANY,
            libc::CONNECT_DATA_IDEMPOTENT /* Enable TFO */ | libc::CONNECT_RESUME_ON_READ_WRITE, /* Send SYN with subsequence send/recv */
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        );

        if ret != 0 {
            error!("Failed to connect to {} with TFO enabled, supported after Mac OS X 10.11, iOS 9.0, tvOS 9.0, watchOS 2.0", addr);

            let _ = libc::close(sockfd);
            return Err(Error::last_os_error());
        }

        let stream = net::TcpStream::from_raw_fd(sockfd);
        TcpStream::from_std(stream)
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
