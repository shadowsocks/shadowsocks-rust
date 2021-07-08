use std::{
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream},
    ops::{Deref, DerefMut},
    os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket},
    pin::Pin,
    ptr,
    task::{self, Poll},
};

use futures::ready;
use log::{debug, error, warn};
use once_cell::sync::Lazy;
use pin_project::pin_project;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};
use winapi::{
    ctypes::{c_char, c_int},
    shared::{
        minwindef::{BOOL, DWORD, FALSE, LPDWORD, LPVOID, TRUE},
        winerror::ERROR_IO_PENDING,
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
        minwinbase::{LPOVERLAPPED, OVERLAPPED},
        mswsock::{LPFN_CONNECTEX, SIO_UDP_CONNRESET, SO_UPDATE_CONNECT_CONTEXT, WSAID_CONNECTEX},
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
            SOL_SOCKET,
            WSA_IO_INCOMPLETE,
        },
    },
};

use crate::net::{
    sys::{set_common_sockopt_after_connect, set_common_sockopt_for_connect},
    AddrFamily,
    ConnectOpts,
};

// ws2ipdef.h
// FIXME: Use winapi's definition if issue resolved
// https://github.com/retep998/winapi-rs/issues/856
const TCP_FASTOPEN: DWORD = 15;

static PFN_CONNECTEX_OPT: Lazy<LPFN_CONNECTEX> = Lazy::new(|| unsafe {
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
        let e = io::Error::from_raw_os_error(err);

        warn!("Failed to get ConnectEx function from WSA extension, error: {}", e);
    }

    let _ = closesocket(socket);

    connectex
});

enum TcpStreamState {
    Connected,
    FastOpenConnect(SocketAddr),
    FastOpenConnecting(Box<OVERLAPPED>),
}

// unsafe: OVERLAPPED can be sent between threads
unsafe impl Send for TcpStreamState {}
unsafe impl Sync for TcpStreamState {}

/// A `TcpStream` that supports TFO (TCP Fast Open)
#[pin_project(project = TcpStreamProj)]
pub struct TcpStream {
    #[pin]
    inner: TokioTcpStream,
    state: TcpStreamState,
}

impl TcpStream {
    pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        set_common_sockopt_for_connect(addr, &socket, opts)?;

        if !opts.tcp.fastopen {
            // If TFO is not enabled, it just works like a normal TcpStream
            let stream = socket.connect(addr).await?;
            set_common_sockopt_after_connect(&stream, opts)?;

            return Ok(TcpStream {
                inner: stream,
                state: TcpStreamState::Connected,
            });
        }

        let sock = socket.as_raw_socket() as SOCKET;

        unsafe {
            // TCP_FASTOPEN was supported since Windows 10

            // Enable TCP_FASTOPEN option

            let enable: DWORD = 1;

            let ret = setsockopt(
                sock,
                IPPROTO_TCP as c_int,
                TCP_FASTOPEN as c_int,
                &enable as *const _ as *const c_char,
                mem::size_of_val(&enable) as c_int,
            );

            if ret == SOCKET_ERROR {
                let err = io::Error::from_raw_os_error(WSAGetLastError());
                error!("set TCP_FASTOPEN error: {}", err);
                return Err(err);
            }

            if opts.bind_local_addr.is_none() {
                // Bind to a dummy address (required)
                let mut dummy_addr: SOCKADDR_IN = mem::zeroed();
                match addr.ip() {
                    IpAddr::V4(..) => dummy_addr.sin_family = AF_INET as ADDRESS_FAMILY,
                    IpAddr::V6(..) => dummy_addr.sin_family = AF_INET6 as ADDRESS_FAMILY,
                }

                let ret = bind(
                    sock,
                    &dummy_addr as *const _ as *const SOCKADDR,
                    mem::size_of_val(&dummy_addr) as c_int,
                );

                if ret == SOCKET_ERROR {
                    let err = WSAGetLastError();
                    return Err(io::Error::from_raw_os_error(err));
                }
            }
        }

        let stream = TokioTcpStream::from_std(unsafe { StdTcpStream::from_raw_socket(socket.into_raw_socket()) })?;
        set_common_sockopt_after_connect(&stream, opts)?;

        Ok(TcpStream {
            inner: stream,
            state: TcpStreamState::FastOpenConnect(addr),
        })
    }
}

impl Deref for TcpStream {
    type Target = TokioTcpStream;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TcpStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

fn set_update_connect_context(sock: SOCKET) -> io::Result<()> {
    unsafe {
        // Make getpeername work
        // https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex
        let ret = setsockopt(sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, ptr::null(), 0);
        if ret == SOCKET_ERROR {
            let err = WSAGetLastError();
            return Err(io::Error::from_raw_os_error(err));
        }
    }

    Ok(())
}

impl AsyncWrite for TcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let TcpStreamProj { inner, state } = self.as_mut().project();

            match *state {
                TcpStreamState::Connected => return inner.poll_write(cx, buf),

                TcpStreamState::FastOpenConnect(addr) => {
                    let saddr = SockAddr::from(addr);

                    unsafe {
                        // https://docs.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex
                        let connect_ex = PFN_CONNECTEX_OPT
                            .expect("LPFN_CONNECTEX function doesn't exist. It is only supported after Windows 10");

                        let sock = inner.as_raw_socket() as SOCKET;

                        let mut overlapped: Box<OVERLAPPED> = Box::new(mem::zeroed());

                        let mut bytes_sent: DWORD = 0;
                        let ret: BOOL = connect_ex(
                            sock,
                            saddr.as_ptr(),
                            saddr.len() as c_int,
                            buf.as_ptr() as PVOID,
                            buf.len() as DWORD,
                            &mut bytes_sent as LPDWORD,
                            overlapped.as_mut() as LPOVERLAPPED,
                        );

                        if ret == TRUE {
                            // Connected successfully.

                            // Make getpeername() works
                            set_update_connect_context(sock)?;

                            debug_assert!(bytes_sent as usize <= buf.len());

                            *state = TcpStreamState::Connected;
                            return Ok(bytes_sent as usize).into();
                        }

                        let err = WSAGetLastError();
                        if err != ERROR_IO_PENDING as c_int {
                            return Err(io::Error::from_raw_os_error(err)).into();
                        }

                        // ConnectEx pending (ERROR_IO_PENDING), check later in FastOpenConnecting
                        *state = TcpStreamState::FastOpenConnecting(overlapped);
                    }
                }

                TcpStreamState::FastOpenConnecting(ref mut overlapped) => {
                    let stream = inner.get_mut();

                    ready!(stream.poll_write_ready(cx))?;

                    let write_result = stream.try_io(Interest::WRITABLE, || {
                        unsafe {
                            let sock = stream.as_raw_socket() as SOCKET;

                            let mut bytes_sent: DWORD = 0;
                            let mut flags: DWORD = 0;

                            // Fetch ConnectEx's result in a non-blocking way.
                            let ret: BOOL = WSAGetOverlappedResult(
                                sock,
                                overlapped.as_mut() as LPOVERLAPPED,
                                &mut bytes_sent as LPDWORD,
                                FALSE, // fWait = false, non-blocking, returns WSA_IO_INCOMPLETE
                                &mut flags as LPDWORD,
                            );

                            if ret == TRUE {
                                // Get ConnectEx's result successfully. Socket is connected

                                // Make getpeername() works
                                set_update_connect_context(sock)?;

                                debug_assert!(bytes_sent as usize <= buf.len());

                                return Ok(bytes_sent as usize);
                            }

                            let err = WSAGetLastError();
                            if err == WSA_IO_INCOMPLETE {
                                // ConnectEx is still not connected. Wait for the next round
                                //
                                // Let `try_io` clears the write readiness.
                                Err(ErrorKind::WouldBlock.into())
                            } else {
                                Err(io::Error::from_raw_os_error(err))
                            }
                        }
                    });

                    match write_result {
                        Ok(n) => {
                            // Connect successfully with fast open
                            *state = TcpStreamState::Connected;
                            return Ok(n).into();
                        }
                        Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                            // Wait again for writable event.
                        }
                        Err(err) => return Err(err).into(),
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// Enable `TCP_FASTOPEN`
///
/// Program borrowed from
/// https://social.msdn.microsoft.com/Forums/en-US/94d1fe8e-4f17-4b28-89eb-1ac776a2e134/how-to-create-tcp-fast-open-connections-with-winsock-?forum=windowsgeneraldevelopmentissues
///
/// TCP_FASTOPEN document
/// https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options
///
/// TCP_FASTOPEN is supported since Windows 10
pub fn set_tcp_fastopen<S: AsRawSocket>(socket: &S) -> io::Result<()> {
    let enable: DWORD = 1;

    unsafe {
        let ret = setsockopt(
            socket.as_raw_socket() as SOCKET,
            IPPROTO_TCP as c_int,
            TCP_FASTOPEN as c_int,
            &enable as *const _ as *const c_char,
            mem::size_of_val(&enable) as c_int,
        );

        if ret == SOCKET_ERROR {
            let err = io::Error::from_raw_os_error(WSAGetLastError());
            error!("set TCP_FASTOPEN error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

fn disable_connection_reset(socket: &UdpSocket) -> io::Result<()> {
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

    Ok(())
}

/// Create a `UdpSocket` binded to `addr`
///
/// It also disables `WSAECONNRESET` for UDP socket
pub async fn create_inbound_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    let set_dual_stack = if let SocketAddr::V6(ref v6) = *addr {
        v6.ip().is_unspecified()
    } else {
        false
    };

    let socket = if !set_dual_stack {
        UdpSocket::bind(addr).await?
    } else {
        let socket = Socket::new(Domain::for_address(*addr), Type::DGRAM, Some(Protocol::UDP))?;

        if let Err(err) = socket.set_only_v6(false) {
            warn!("failed to set IPV6_V6ONLY: false for listener, error: {}", err);

            // This is not a fatal error, just warn and skip
        }

        let saddr = SockAddr::from(*addr);

        match socket.bind(&saddr) {
            Ok(..) => {}
            Err(ref err) if err.kind() == ErrorKind::AddrInUse => {
                // This is probably 0.0.0.0 with the same port has already been occupied
                debug!(
                    "0.0.0.0:{} may have already been occupied, retry with IPV6_V6ONLY",
                    addr.port()
                );

                if let Err(err) = socket.set_only_v6(true) {
                    warn!("failed to set IPV6_V6ONLY: true for listener, error: {}", err);

                    // This is not a fatal error, just warn and skip
                }
                socket.bind(&saddr)?;
            }
            Err(err) => return Err(err),
        }

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())?
    };

    disable_connection_reset(&socket)?;
    Ok(socket)
}

/// Create a `UdpSocket` for connecting to `addr`
#[inline(always)]
pub async fn create_outbound_udp_socket(af: AddrFamily, opts: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, opts.bind_local_addr) {
        (AddrFamily::Ipv4, Some(IpAddr::V4(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv6, Some(IpAddr::V6(ip))) => SocketAddr::new(ip.into(), 0),
        (AddrFamily::Ipv4, ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (AddrFamily::Ipv6, ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    disable_connection_reset(&socket)?;

    Ok(socket)
}
