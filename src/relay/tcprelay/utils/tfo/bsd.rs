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
        // TCP_FASTOPEN was supported since FreeBSD 12.0
        //
        // Example program:
        // https://people.freebsd.org/~pkelsey/tfo-tools/tfo-srv.c

        let enable: libc::c_int = 1;

        let ret = libc::setsockopt(
            fd,
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
            return Err(Error::last_os_error());
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
