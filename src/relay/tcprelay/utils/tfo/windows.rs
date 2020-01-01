//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{self, IpAddr, SocketAddr},
    os::windows::io::AsRawSocket,
};

use log::error;
use net2::TcpBuilder;
use tokio::net::{TcpListener, TcpStream};
use winapi::{
    ctypes::{c_char, c_int},
    shared::{
        minwindef::DWORD,
        ws2def::{ADDRESS_FAMILY, AF_INET, AF_INET6, IPPROTO_TCP, SOCKADDR, SOCKADDR_IN},
    },
    um::winsock2::{bind, connect, setsockopt, WSAGetLastError, SOCKET, SOCKET_ERROR},
};

// ws2ipdef.h
// FIXME: Use winapi's definition if issue resolved
// https://github.com/retep998/winapi-rs/issues/856
const TCP_FASTOPEN: DWORD = 15;

pub async fn bind_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let listener = net::TcpListener::bind(addr)?;

    let socket = listener.as_raw_socket() as SOCKET;
    unsafe {
        // Program borrowed from
        // https://social.msdn.microsoft.com/Forums/en-US/94d1fe8e-4f17-4b28-89eb-1ac776a2e134/how-to-create-tcp-fast-open-connections-with-winsock-?forum=windowsgeneraldevelopmentissues
        //
        // TCP_FASTOPEN document
        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options
        //
        // TCP_FASTOPEN is supported since Windows 10

        let enable: DWORD = 1;

        let ret = setsockopt(
            socket,
            IPPROTO_TCP as c_int,
            TCP_FASTOPEN as c_int,
            &enable as *const _ as *const c_char,
            mem::size_of_val(&enable) as c_int,
        );

        if ret == SOCKET_ERROR {
            error!(
                "Failed to listen on {} with TFO enabled, supported after Windows 10",
                addr
            );

            let err = WSAGetLastError();
            return Err(Error::from_raw_os_error(err));
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
    let socket = stream.as_raw_socket() as SOCKET;

    unsafe {
        // TCP_FASTOPEN was supported since Windows 10

        // Enable TCP_FASTOPEN option

        let enable: DWORD = 1;

        let ret = setsockopt(
            socket,
            IPPROTO_TCP as c_int,
            TCP_FASTOPEN as c_int,
            &enable as *const _ as *const c_char,
            mem::size_of_val(&enable) as c_int,
        );

        if ret == SOCKET_ERROR {
            error!(
                "Failed to connect to {} with TFO enabled, supported after Windows 10",
                addr
            );

            let err = WSAGetLastError();
            return Err(Error::from_raw_os_error(err));
        }

        // Bind to a dummy address (required)
        let mut dummy_addr: SOCKADDR_IN = mem::zeroed();
        match addr.ip() {
            IpAddr::V4(..) => dummy_addr.sin_family = AF_INET as ADDRESS_FAMILY,
            IpAddr::V6(..) => dummy_addr.sin_family = AF_INET6 as ADDRESS_FAMILY,
        }

        let ret = bind(
            socket,
            &dummy_addr as *const _ as *const SOCKADDR,
            mem::size_of_val(&dummy_addr) as c_int,
        );

        if ret == SOCKET_ERROR {
            let err = WSAGetLastError();
            return Err(Error::from_raw_os_error(err));
        }

        // FIXME: MSDN suggests to use ConnectEx instead of connect
        // But it requires dynamic load from WSAIoctl and cache it in a global variable
        // That sucks.

        let (saddr, saddr_len) = addr2raw(addr);
        let ret = connect(socket, saddr, saddr_len);

        if ret == SOCKET_ERROR {
            let err = WSAGetLastError();
            return Err(Error::from_raw_os_error(err));
        }
    }

    TcpStream::from_std(stream)
}

// Borrowed from net2
fn addr2raw(addr: &SocketAddr) -> (*const SOCKADDR, c_int) {
    use std::mem;

    match *addr {
        SocketAddr::V4(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as c_int),
        SocketAddr::V6(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as c_int),
    }
}
