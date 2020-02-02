use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    os::windows::io::AsRawSocket,
    ptr,
};

use mio::net::UdpSocket as MioUdpSocket;
use socket2::Socket;
use tokio::net::UdpSocket as TokioUdpSocket;
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, LPDWORD, LPVOID},
    um::{
        mswsock::SIO_UDP_CONNRESET,
        winsock2::{WSAGetLastError, WSAIoctl, SOCKET, SOCKET_ERROR},
    },
};

/// Create a `UdpSocket` binded to `addr`
///
/// It also disables `WSAECONNRESET` for UDP socket
pub async fn create_socket(addr: &SocketAddr) -> io::Result<TokioUdpSocket> {
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

    TokioUdpSocket::from_std(socket)
}

pub fn check_support_tproxy() -> io::Result<()> {
    // Windows seems to support transparent proxy, but I haven't found any useful document about it

    let err = Error::new(ErrorKind::Other, "Windows doesn't support UDP transparent proxy");
    Err(err)
}

pub fn set_socket_before_bind(_addr: &SocketAddr, _socket: &Socket) -> io::Result<()> {
    unimplemented!("Windows doesn't support UDP transparent proxy");
}

pub fn recv_from_with_destination(
    _socket: &MioUdpSocket,
    _buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unimplemented!("Windows doesn't support UDP transparent proxy");
}
