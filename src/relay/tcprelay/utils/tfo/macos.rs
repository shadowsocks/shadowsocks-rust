//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{self, IpAddr, SocketAddr},
    os::unix::io::AsRawFd,
    ptr,
};

use libc;
use log::error;
use net2::TcpBuilder;
use tokio::net::{TcpListener, TcpStream};

pub async fn bind_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let listener = net::TcpListener::bind(addr)?;

    let fd = listener.as_raw_fd();

    unsafe {
        // TCP_FASTOPEN was supported since
        // macosx(10.11), ios(9.0), tvos(9.0), watchos(2.0)

        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            error!("Failed to listen on {} with TFO enabled, supported after Mac OS X 10.11, iOS 9.0, tvOS 9.0, watchOS 2.0", addr);

            return Err(Error::from_raw_os_error(*libc::__error()));
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

            return Err(Error::from_raw_os_error(*libc::__error()));
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
