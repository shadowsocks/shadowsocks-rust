//! Utility functions

use std::{
    io,
    net::{SocketAddr, TcpStream as StdTcpStream},
};

use tokio::net::TcpStream as TokioTcpStream;
#[cfg(windows)]
use winapi::um::winsock2::SOCKET;

use crate::relay::utils::{bind_socket, close_socket, create_socket_nonblock};

#[cfg(unix)]
fn new_socket(addr: &SocketAddr) -> io::Result<libc::c_int> {
    let domain = match *addr {
        SocketAddr::V4(..) => libc::AF_INET,
        SocketAddr::V6(..) => libc::AF_INET6,
    };

    create_socket_nonblock(domain, libc::SOCK_STREAM)
}

#[cfg(windows)]
fn new_socket(addr: &SocketAddr) -> io::Result<SOCKET> {
    use winapi::um::winsock2::{PF_INET, PF_INET6, SOCK_STREAM};

    let af = match *addr {
        SocketAddr::V4(..) => PF_INET,
        SocketAddr::V6(..) => PF_INET6,
    };

    create_socket_nonblock(af, SOCK_STREAM)
}

#[cfg(unix)]
fn create_tcp_stream(socket: libc::c_int) -> StdTcpStream {
    use std::os::unix::io::FromRawFd;
    unsafe { StdTcpStream::from_raw_fd(socket) }
}

#[cfg(windows)]
fn create_tcp_stream(socket: SOCKET) -> StdTcpStream {
    use std::os::windows::io::{FromRawSocket, RawSocket};
    unsafe { StdTcpStream::from_raw_socket(socket as RawSocket) }
}

pub async fn connect_tcp_stream(addr: &SocketAddr, outbound_addr: &Option<SocketAddr>) -> io::Result<TokioTcpStream> {
    let socket = new_socket(addr)?;

    if let Some(ref bind_addr) = outbound_addr {
        if let Err(err) = bind_socket(socket, bind_addr) {
            let _ = close_socket(socket);
            return Err(err);
        }
    }

    let stream = create_tcp_stream(socket);

    // FIXME: connect_std is marked as not recommended
    TokioTcpStream::connect_std(stream, addr).await
}
