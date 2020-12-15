use std::{
    io,
    mem,
    net::{IpAddr, SocketAddr},
    os::windows::io::AsRawSocket,
    ptr,
};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, LPDWORD, LPVOID},
    um::{
        mswsock::SIO_UDP_CONNRESET,
        winsock2::{WSAGetLastError, WSAIoctl, SOCKET, SOCKET_ERROR},
    },
};

use crate::config::ConnectOpts;

/// Create a `UdpSocket` binded to `addr`
///
/// It also disables `WSAECONNRESET` for UDP socket
pub async fn create_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;
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

    Ok(socket)
}

/// create a new TCP stream
#[inline(always)]
pub async fn tcp_stream_connect(saddr: &SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
    if let Some(ip) = opts.bind_local_addr {
        let socket = match *saddr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        // Binds to IP address
        if let Some(ip) = config.bind_local_addr {
            match (ip, saddr.ip()) {
                (IpAddr::V4(..), IpAddr::V4(..)) => {
                    socket.bind(SocketAddr::new(ip, 0))?;
                }
                (IpAddr::V6(..), IpAddr::V6(..)) => {
                    socket.bind(SocketAddr::new(ip, 0))?;
                }
                _ => {}
            }
        }

        // it's important that the socket is binded before connecting
        socket.connect(*saddr).await
    } else {
        TcpStream::connect(saddr).await
    }
}

/// Create a `UdpSocket` for connecting to `addr`
#[inline(always)]
pub async fn create_outbound_udp_socket(addr: &SocketAddr, opts: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (addr.ip(), opts.bind_local_addr) {
        (IpAddr::V4(..), Some(IpAddr::V4(ip))) => SocketAddr::new(ip.into(), 0),
        (IpAddr::V6(..), Some(IpAddr::V6(ip))) => SocketAddr::new(ip.into(), 0),
        (IpAddr::V4(..), ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (IpAddr::V6(..), ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    create_udp_socket(&bind_addr).await
}
