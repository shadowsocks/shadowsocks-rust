//! TCP Fast Open wrappers

use std::{
    io::{self, Error},
    mem,
    net::{self, IpAddr, SocketAddr},
    os::windows::io::AsRawSocket,
    ptr,
};

use lazy_static::lazy_static;
use log::{error, warn};
use net2::TcpBuilder;
use tokio::net::{TcpListener, TcpStream};
use winapi::{
    ctypes::{c_char, c_int},
    shared::{
        minwindef::{BOOL, DWORD, FALSE, LPDWORD, LPVOID, TRUE},
        ws2def::{
            ADDRESS_FAMILY,
            AF_INET,
            AF_INET6,
            IPPROTO_TCP,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            SOCKADDR,
            SOCKADDR_IN,
        },
    },
    um::{
        minwinbase::OVERLAPPED,
        mswsock::{LPFN_CONNECTEX, WSAID_CONNECTEX},
        winnt::PVOID,
        winsock2::{
            bind,
            closesocket,
            setsockopt,
            socket,
            WSAGetLastError,
            WSAGetOverlappedResult,
            WSAIoctl,
            INVALID_SOCKET,
            SOCKET,
            SOCKET_ERROR,
            SOCK_STREAM,
        },
    },
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

lazy_static! {
    static ref PFN_CONNECTEX_OPT: LPFN_CONNECTEX = unsafe {
        let socket = socket(AF_INET, SOCK_STREAM, 0);
        if socket == INVALID_SOCKET {
            return None;
        }

        let mut guid = WSAID_CONNECTEX;
        let mut num_bytes: DWORD = 0;

        let mut connectex: LPFN_CONNECTEX = None;

        let ret = WSAIoctl(
            socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &mut guid as *mut _ as LPVOID,
            mem::size_of_val(&guid) as DWORD,
            &mut connectex as *mut _ as LPVOID,
            mem::size_of_val(&connectex) as DWORD,
            &mut num_bytes as *mut _,
            ptr::null_mut(),
            None,
        );

        if ret != 0 {
            let err = WSAGetLastError();
            let e = Error::from_raw_os_error(err);

            warn!("Failed to get ConnectEx function from WSA extension, error: {}", e);
        }

        let _ = closesocket(socket);

        connectex
    };
}

pub struct ConnectContext {
    // Reference to the partial connected socket fd
    // This struct doesn't own the HANDLE, so do not close it while dropping
    socket: SOCKET,

    // Target address for calling `ConnectEx`
    remote_addr: SocketAddr,
}

impl ConnectContext {
    /// Performing actual connect operation
    pub fn connect_with_data(self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            // https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex
            let connect_ex = PFN_CONNECTEX_OPT.expect("LPFN_CONNECTEX function doesn't exists");
            let (saddr, saddr_len) = addr2raw(&self.remote_addr);

            let mut overlapped: OVERLAPPED = mem::zeroed();

            let mut bytes_sent: DWORD = 0;
            let ret: BOOL = connect_ex(
                self.socket,
                saddr,
                saddr_len,
                buf.as_ptr() as PVOID,
                buf.len() as DWORD,
                &mut bytes_sent as *mut _ as LPDWORD,
                &mut overlapped as *mut _,
            );

            if ret == FALSE {
                let mut bytes_sent: DWORD = 0;
                let mut flags: DWORD = 0;

                // FIXME: Blocking call.
                let ret: BOOL = WSAGetOverlappedResult(
                    self.socket,
                    &mut overlapped as *mut _,
                    &mut bytes_sent as LPDWORD,
                    TRUE,
                    &mut flags as LPDWORD,
                );

                if ret == TRUE {
                    Ok(bytes_sent as usize)
                } else {
                    let err = WSAGetLastError();
                    Err(Error::from_raw_os_error(err))
                }
            } else {
                // Connect succeeded
                Ok(bytes_sent as usize)
            }
        }
    }
}

pub async fn connect_stream(addr: &SocketAddr) -> io::Result<(TcpStream, ConnectContext)> {
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
    }

    TcpStream::from_std(stream).map(|s| {
        (
            s,
            ConnectContext {
                socket,
                remote_addr: *addr,
            },
        )
    })
}

// Borrowed from net2
fn addr2raw(addr: &SocketAddr) -> (*const SOCKADDR, c_int) {
    use std::mem;

    match *addr {
        SocketAddr::V4(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as c_int),
        SocketAddr::V6(ref a) => (a as *const _ as *const _, mem::size_of_val(a) as c_int),
    }
}
