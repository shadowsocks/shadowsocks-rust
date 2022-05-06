use std::{
    ffi::{c_void, CString},
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::io::{AsRawSocket, FromRawSocket, IntoRawSocket, RawSocket},
    pin::Pin,
    ptr,
    task::{self, Poll},
};

use log::{error, warn};
use pin_project::pin_project;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};
use tokio_tfo::TfoStream;
use windows_sys::{
    core::PCSTR,
    Win32::{
        Foundation::BOOL,
        NetworkManagement::IpHelper::if_nametoindex,
        Networking::WinSock::{
            setsockopt,
            WSAGetLastError,
            WSAIoctl,
            IPPROTO_IP,
            IPPROTO_IPV6,
            IPPROTO_TCP,
            IPV6_MTU_DISCOVER,
            IPV6_UNICAST_IF,
            IP_MTU_DISCOVER,
            IP_PMTUDISC_DO,
            IP_UNICAST_IF,
            SIO_UDP_CONNRESET,
            SOCKET,
            SOCKET_ERROR,
            TCP_FASTOPEN,
        },
    },
};

// BOOL values
const FALSE: BOOL = 0;

use crate::net::{
    is_dual_stack_addr,
    sys::{set_common_sockopt_for_connect, socket_bind_dual_stack},
    AddrFamily,
    ConnectOpts,
};

/// A `TcpStream` that supports TFO (TCP Fast Open)
#[pin_project(project = TcpStreamProj)]
pub enum TcpStream {
    Standard(#[pin] TokioTcpStream),
    FastOpen(#[pin] TfoStream),
}

impl TcpStream {
    pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<TcpStream> {
        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        // Binds to a specific network interface (device)
        if let Some(ref iface) = opts.bind_interface {
            set_ip_unicast_if(&socket, addr, iface)?;
        }

        set_common_sockopt_for_connect(addr, &socket, opts)?;

        if !opts.tcp.fastopen {
            // If TFO is not enabled, it just works like a normal TcpStream
            let stream = socket.connect(addr).await?;
            set_common_sockopt_after_connect(&stream, opts)?;

            return Ok(TcpStream::Standard(stream));
        }

        let stream = TfoStream::connect_with_socket(socket, addr).await?;
        set_common_sockopt_after_connect(&stream, opts)?;

        Ok(TcpStream::FastOpen(stream))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            TcpStream::Standard(ref s) => s.local_addr(),
            TcpStream::FastOpen(ref s) => s.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            TcpStream::Standard(ref s) => s.peer_addr(),
            TcpStream::FastOpen(ref s) => s.peer_addr(),
        }
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        match *self {
            TcpStream::Standard(ref s) => s.nodelay(),
            TcpStream::FastOpen(ref s) => s.nodelay(),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match *self {
            TcpStream::Standard(ref s) => s.set_nodelay(nodelay),
            TcpStream::FastOpen(ref s) => s.set_nodelay(nodelay),
        }
    }
}

impl AsRawSocket for TcpStream {
    fn as_raw_socket(&self) -> RawSocket {
        match *self {
            TcpStream::Standard(ref s) => s.as_raw_socket(),
            TcpStream::FastOpen(ref s) => s.as_raw_socket(),
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_read(cx, buf),
            TcpStreamProj::FastOpen(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_write(cx, buf),
            TcpStreamProj::FastOpen(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_flush(cx),
            TcpStreamProj::FastOpen(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            TcpStreamProj::Standard(s) => s.poll_shutdown(cx),
            TcpStreamProj::FastOpen(s) => s.poll_shutdown(cx),
        }
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
    let enable: u32 = 1;

    unsafe {
        let ret = setsockopt(
            socket.as_raw_socket() as SOCKET,
            IPPROTO_TCP as i32,
            TCP_FASTOPEN as i32,
            &enable as *const _ as PCSTR,
            mem::size_of_val(&enable) as i32,
        );

        if ret == SOCKET_ERROR {
            let err = io::Error::from_raw_os_error(WSAGetLastError());
            error!("set TCP_FASTOPEN error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

fn set_ip_unicast_if<S: AsRawSocket>(socket: &S, addr: SocketAddr, iface: &str) -> io::Result<()> {
    let handle = socket.as_raw_socket() as SOCKET;

    unsafe {
        // Windows if_nametoindex requires a C-string for interface name
        let ifname = CString::new(iface).expect("iface");

        // https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff553788(v=vs.85)
        let if_index = if_nametoindex(ifname.as_ptr() as PCSTR);
        if if_index == 0 {
            // If the if_nametoindex function fails and returns zero, it is not possible to determine an error code.
            error!("if_nametoindex {} fails", iface);
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid interface name"));
        }

        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        let ret = match addr {
            SocketAddr::V4(..) => setsockopt(
                handle,
                IPPROTO_IP as i32,
                IP_UNICAST_IF as i32,
                &if_index as *const _ as PCSTR,
                mem::size_of_val(&if_index) as i32,
            ),
            SocketAddr::V6(..) => setsockopt(
                handle,
                IPPROTO_IPV6 as i32,
                IPV6_UNICAST_IF as i32,
                &if_index as *const _ as PCSTR,
                mem::size_of_val(&if_index) as i32,
            ),
        };

        if ret == SOCKET_ERROR {
            let err = io::Error::from_raw_os_error(WSAGetLastError());
            error!("set IP_UNICAST_IF / IPV6_UNICAST_IF error: {}", err);
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

        let mut bytes_returned: u32 = 0;
        let enable: BOOL = FALSE;

        let ret = WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            &enable as *const _ as *const c_void,
            mem::size_of_val(&enable) as u32,
            ptr::null_mut(),
            0,
            &mut bytes_returned as *mut _,
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

/// Disable IP fragmentation
#[inline]
pub fn set_disable_ip_fragmentation<S: AsRawSocket>(af: AddrFamily, socket: &S) -> io::Result<()> {
    let handle = socket.as_raw_socket() as SOCKET;

    unsafe {
        // For Windows, IP_MTU_DISCOVER should be enabled for both IPv4 and IPv6 sockets
        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        let value = IP_PMTUDISC_DO;
        let ret = setsockopt(
            handle,
            IPPROTO_IP as i32,
            IP_MTU_DISCOVER as i32,
            &value as *const _ as PCSTR,
            mem::size_of_val(&value) as i32,
        );

        if ret == SOCKET_ERROR {
            let err = io::Error::from_raw_os_error(WSAGetLastError());
            return Err(err);
        }

        if af == AddrFamily::Ipv6 {
            let value = IP_PMTUDISC_DO;
            let ret = setsockopt(
                handle,
                IPPROTO_IPV6 as i32,
                IPV6_MTU_DISCOVER as i32,
                &value as *const _ as PCSTR,
                mem::size_of_val(&value) as i32,
            );

            if ret == SOCKET_ERROR {
                let err = io::Error::from_raw_os_error(WSAGetLastError());
                return Err(err);
            }
        }
    }

    Ok(())
}

/// Create a `UdpSocket` binded to `addr`
///
/// It also disables `WSAECONNRESET` for UDP socket
pub async fn create_inbound_udp_socket(addr: &SocketAddr, ipv6_only: bool) -> io::Result<UdpSocket> {
    let set_dual_stack = is_dual_stack_addr(addr);

    let socket = if !set_dual_stack {
        UdpSocket::bind(addr).await?
    } else {
        let socket = Socket::new(Domain::for_address(*addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket_bind_dual_stack(&socket, addr, ipv6_only)?;

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())?
    };

    let addr_family = match addr {
        SocketAddr::V4(..) => AddrFamily::Ipv4,
        SocketAddr::V6(..) => AddrFamily::Ipv6,
    };
    if let Err(err) = set_disable_ip_fragmentation(addr_family, &socket) {
        warn!("failed to disable IP fragmentation, error: {}", err);
    }
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

    let socket = if af != AddrFamily::Ipv6 {
        UdpSocket::bind(bind_addr).await?
    } else {
        let socket = Socket::new(Domain::for_address(bind_addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket_bind_dual_stack(&socket, &bind_addr, false)?;

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())?
    };

    if let Err(err) = set_disable_ip_fragmentation(af, &socket) {
        warn!("failed to disable IP fragmentation, error: {}", err);
    }
    disable_connection_reset(&socket)?;

    if let Some(ref iface) = opts.bind_interface {
        set_ip_unicast_if(&socket, bind_addr, iface)?;
    }

    Ok(socket)
}

pub fn set_common_sockopt_after_connect<S: AsRawSocket>(stream: &S, opts: &ConnectOpts) -> io::Result<()> {
    let socket = unsafe { Socket::from_raw_socket(stream.as_raw_socket()) };

    macro_rules! try_sockopt {
        ($socket:ident . $func:ident ($($arg:expr),*)) => {
            match $socket . $func ($($arg),*) {
                Ok(e) => e,
                Err(err) => {
                    let _ = socket.into_raw_socket();
                    return Err(err);
                }
            }
        };
    }

    if opts.tcp.nodelay {
        try_sockopt!(socket.set_nodelay(true));
    }

    if let Some(keepalive_duration) = opts.tcp.keepalive {
        let keepalive = TcpKeepalive::new()
            .with_time(keepalive_duration)
            .with_interval(keepalive_duration);
        try_sockopt!(socket.set_tcp_keepalive(&keepalive));
    }

    let _ = socket.into_raw_socket();
    Ok(())
}
