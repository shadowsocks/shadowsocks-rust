use std::{
    io,
    mem,
    net::{SocketAddr, TcpStream},
    os::windows::io::AsRawSocket,
    ptr,
};

use net2::*;
use tokio::net::UdpSocket;
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, LPDWORD, LPVOID},
    um::{
        mswsock::SIO_UDP_CONNRESET,
        winsock2::{WSAGetLastError, WSAIoctl, SOCKET, SOCKET_ERROR},
    },
};

use crate::context::Context;

/// Create a `UdpSocket` binded to `addr`
///
/// It also disables `WSAECONNRESET` for UDP socket
pub async fn create_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    // FIXME: Temporary solution. Should be replaced by tokio's UdpSocket::as_raw_socket
    // https://github.com/tokio-rs/tokio/issues/2017

    let socket = ::std::net::UdpSocket::bind(addr)?;
    let handle = socket.as_raw_socket() as SOCKET;

    unsafe {
        // Ignoring UdpSocket's WSAECONNRESET error
        // https://github.com/shadowsocks/shadowsocks-rust/issues/179
        // https://stackoverflow.com/questions/30749423/is-winsock-error-10054-wsaeconnreset-normal-with-udp-to-from-localhost
        //
        // This is because `UdpSocket::recv_from` may return WSAECONNRESET
        // if you called `UdpSocket::send_to` a destination that is not existed (may be closed).
        //
        // It is not an error. Could be ignored completely.
        // We have to ignore it here because it will crash the server.

        let mut bytes_returned: DWORD = 0;
        let mut enable: BOOL = FALSE;

        let ret = WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            &mut enable as *mut _ as LPVOID,
            mem::size_of_val(&enable) as DWORD,
            ptr::null_mut(),
            0,
            &mut bytes_returned as *mut _ as LPDWORD,
            ptr::null_mut(),
            None,
        );

        if ret == SOCKET_ERROR {
            use std::io::Error;

            // Error occurs
            let err_code = WSAGetLastError();
            return Err(Error::from_raw_os_error(err_code));
        }
    }

    UdpSocket::from_std(socket)
}

/// create a new TCP stream
#[inline(always)]
pub fn new_tcp_stream(saddr: &SocketAddr, _context: &Context) -> io::Result<TcpStream> {
    let builder = match saddr {
        SocketAddr::V4(_) => TcpBuilder::new_v4()?,
        SocketAddr::V6(_) => TcpBuilder::new_v6()?,
    };

    builder.to_tcp_stream()
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_udp_socket_with_context(addr: &SocketAddr, _context: &Context) -> io::Result<UdpSocket> {
    create_udp_socket(addr).await
}
