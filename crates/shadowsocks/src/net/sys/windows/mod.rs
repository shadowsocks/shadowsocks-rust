use std::{
    cell::RefCell,
    collections::HashMap,
    ffi::{CStr, CString, OsString, c_void},
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawSocket, FromRawSocket, IntoRawSocket, RawSocket},
    },
    pin::Pin,
    ptr, slice,
    task::{self, Poll},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use log::{error, warn};
use pin_project::pin_project;
use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};
use tokio_tfo::TfoStream;
use windows_sys::{
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS, FALSE},
        NetworkManagement::IpHelper::{
            GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
            GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, if_nametoindex,
        },
        Networking::WinSock::{
            AF_UNSPEC, IP_MTU_DISCOVER, IP_PMTUDISC_DO, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP,
            IPV6_MTU_DISCOVER, IPV6_UNICAST_IF, SIO_UDP_CONNRESET, SOCKET, SOCKET_ERROR, TCP_FASTOPEN, WSAGetLastError,
            WSAIoctl, htonl, setsockopt,
        },
    },
    core::{BOOL, PCSTR},
};

use crate::net::{
    AcceptOpts, AddrFamily, ConnectOpts, is_dual_stack_addr,
    sys::{set_common_sockopt_for_connect, socket_bind_dual_stack},
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
            set_ip_unicast_if(&socket, &addr, iface)?;
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

/// Create a TCP socket for listening
pub async fn create_inbound_tcp_socket(bind_addr: &SocketAddr, _accept_opts: &AcceptOpts) -> io::Result<TcpSocket> {
    match bind_addr {
        SocketAddr::V4(..) => TcpSocket::new_v4(),
        SocketAddr::V6(..) => TcpSocket::new_v6(),
    }
}

fn find_adapter_interface_index(addr: &SocketAddr, iface: &str) -> io::Result<Option<u32>> {
    // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses

    let ip = addr.ip();

    unsafe {
        let mut ip_adapter_addresses_buffer = BytesMut::with_capacity(15 * 1024);
        ip_adapter_addresses_buffer.set_len(15 * 1024);

        let mut ip_adapter_addresses_buffer_size: u32 = ip_adapter_addresses_buffer.len() as u32;
        loop {
            let ret = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                ptr::null(),
                ip_adapter_addresses_buffer.as_mut_ptr() as *mut _,
                &mut ip_adapter_addresses_buffer_size as *mut _,
            );

            match ret {
                ERROR_SUCCESS => break,
                ERROR_BUFFER_OVERFLOW => {
                    // resize buffer to ip_adapter_addresses_buffer_size
                    ip_adapter_addresses_buffer.resize(ip_adapter_addresses_buffer_size as usize, 0);
                    continue;
                }
                ERROR_NO_DATA => return Ok(None),
                _ => {
                    let err = io::Error::other(format!("GetAdaptersAddresses failed with error: {}", ret));
                    return Err(err);
                }
            }
        }

        // IP_ADAPTER_ADDRESSES_LH is a linked-list
        let mut current_ip_adapter_address: *mut IP_ADAPTER_ADDRESSES_LH =
            ip_adapter_addresses_buffer.as_mut_ptr() as *mut _;
        while !current_ip_adapter_address.is_null() {
            let ip_adapter_address: &IP_ADAPTER_ADDRESSES_LH = &*current_ip_adapter_address;

            // Friendly Name
            let friendly_name_len: usize = libc::wcslen(ip_adapter_address.FriendlyName);
            let friendly_name_slice: &[u16] = slice::from_raw_parts(ip_adapter_address.FriendlyName, friendly_name_len);
            let friendly_name_os = OsString::from_wide(friendly_name_slice); // UTF-16 to UTF-8
            if let Some(friendly_name) = friendly_name_os.to_str() {
                if friendly_name == iface {
                    match ip {
                        IpAddr::V4(..) => return Ok(Some(ip_adapter_address.Anonymous1.Anonymous.IfIndex)),
                        IpAddr::V6(..) => return Ok(Some(ip_adapter_address.Ipv6IfIndex)),
                    }
                }
            }

            // Adapter Name
            let adapter_name = CStr::from_ptr(ip_adapter_address.AdapterName as *mut _ as *const _);
            if adapter_name.to_bytes() == iface.as_bytes() {
                match ip {
                    IpAddr::V4(..) => return Ok(Some(ip_adapter_address.Anonymous1.Anonymous.IfIndex)),
                    IpAddr::V6(..) => return Ok(Some(ip_adapter_address.Ipv6IfIndex)),
                }
            }

            current_ip_adapter_address = ip_adapter_address.Next;
        }
    }

    Ok(None)
}

fn find_interface_index_cached(addr: &SocketAddr, iface: &str) -> io::Result<u32> {
    const INDEX_EXPIRE_DURATION: Duration = Duration::from_secs(5);

    thread_local! {
        static INTERFACE_INDEX_CACHE: RefCell<HashMap<String, (u32, Instant)>> =
            RefCell::new(HashMap::new());
    }

    let cache_index = INTERFACE_INDEX_CACHE.with(|cache| cache.borrow().get(iface).cloned());
    if let Some((idx, insert_time)) = cache_index {
        // short-path, cache hit for most cases
        let now = Instant::now();
        if now - insert_time < INDEX_EXPIRE_DURATION {
            return Ok(idx);
        }
    }

    // Get from API GetAdaptersAddresses
    let idx = match find_adapter_interface_index(addr, iface)? {
        Some(idx) => idx,
        None => unsafe {
            // Windows if_nametoindex requires a C-string for interface name
            let ifname = CString::new(iface).expect("iface");

            // https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff553788(v=vs.85)
            let if_index = if_nametoindex(ifname.as_ptr() as PCSTR);
            if if_index == 0 {
                // If the if_nametoindex function fails and returns zero, it is not possible to determine an error code.
                error!("if_nametoindex {} fails", iface);
                return Err(io::Error::new(ErrorKind::InvalidInput, "invalid interface name"));
            }

            if_index
        },
    };

    INTERFACE_INDEX_CACHE.with(|cache| {
        cache.borrow_mut().insert(iface.to_owned(), (idx, Instant::now()));
    });

    Ok(idx)
}

fn set_ip_unicast_if<S: AsRawSocket>(socket: &S, addr: &SocketAddr, iface: &str) -> io::Result<()> {
    let handle = socket.as_raw_socket() as SOCKET;

    let if_index = find_interface_index_cached(addr, iface)?;

    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
        let ret = match addr {
            SocketAddr::V4(..) => {
                // Interface index is in network byte order for IPPROTO_IP.
                let if_index = htonl(if_index);
                setsockopt(
                    handle,
                    IPPROTO_IP as i32,
                    IP_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            }
            SocketAddr::V6(..) => {
                // Interface index is in host byte order for IPPROTO_IPV6.
                setsockopt(
                    handle,
                    IPPROTO_IPV6 as i32,
                    IPV6_UNICAST_IF as i32,
                    &if_index as *const _ as PCSTR,
                    mem::size_of_val(&if_index) as i32,
                )
            }
        };

        if ret == SOCKET_ERROR {
            let err = io::Error::from_raw_os_error(WSAGetLastError());
            error!(
                "set IP_UNICAST_IF / IPV6_UNICAST_IF interface: {}, index: {}, error: {}",
                iface, if_index, err
            );
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
        (AddrFamily::Ipv4, Some(SocketAddr::V4(addr))) => addr.into(),
        (AddrFamily::Ipv4, Some(SocketAddr::V6(addr))) => {
            // Map IPv6 bind_local_addr to IPv4 if AF is IPv4
            match addr.ip().to_ipv4_mapped() {
                Some(addr) => SocketAddr::new(addr.into(), 0),
                None => return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid IPv6 address")),
            }
        }
        (AddrFamily::Ipv6, Some(SocketAddr::V6(addr))) => addr.into(),
        (AddrFamily::Ipv6, Some(SocketAddr::V4(addr))) => {
            // Map IPv4 bind_local_addr to IPv6 if AF is IPv6
            SocketAddr::new(addr.ip().to_ipv6_mapped().into(), 0)
        }
        (AddrFamily::Ipv4, ..) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        (AddrFamily::Ipv6, ..) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };

    bind_outbound_udp_socket(&bind_addr, opts).await
}

/// Create a `UdpSocket` binded to `bind_addr`
pub async fn bind_outbound_udp_socket(bind_addr: &SocketAddr, opts: &ConnectOpts) -> io::Result<UdpSocket> {
    let af = AddrFamily::from(bind_addr);

    let socket = Socket::new(Domain::for_address(*bind_addr), Type::DGRAM, Some(Protocol::UDP))?;

    if let Some(ref iface) = opts.bind_interface {
        set_ip_unicast_if(&socket, bind_addr, iface)?;
    }

    // bind() should be called after IP_UNICAST_IF
    if af != AddrFamily::Ipv6 {
        let bind_addr = SockAddr::from(*bind_addr);
        socket.bind(&bind_addr)?;
    } else {
        socket_bind_dual_stack(&socket, bind_addr, false)?;
    }

    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;

    if !opts.udp.allow_fragmentation {
        if let Err(err) = set_disable_ip_fragmentation(af, &socket) {
            warn!("failed to disable IP fragmentation, error: {}", err);
        }
    }
    disable_connection_reset(&socket)?;

    Ok(socket)
}

#[inline(always)]
fn socket_call_warp<S: AsRawSocket, F: FnOnce(&Socket) -> io::Result<()>>(stream: &S, f: F) -> io::Result<()> {
    let socket = unsafe { Socket::from_raw_socket(stream.as_raw_socket()) };
    let result = f(&socket);
    let _ = socket.into_raw_socket();
    result
}

pub fn set_common_sockopt_after_connect<S: AsRawSocket>(stream: &S, opts: &ConnectOpts) -> io::Result<()> {
    socket_call_warp(stream, |socket| set_common_sockopt_after_connect_impl(socket, opts))
}

fn set_common_sockopt_after_connect_impl(socket: &Socket, opts: &ConnectOpts) -> io::Result<()> {
    if opts.tcp.nodelay {
        socket.set_tcp_nodelay(true)?;
    }

    if let Some(intv) = opts.tcp.keepalive {
        let keepalive = TcpKeepalive::new().with_time(intv).with_interval(intv);
        socket.set_tcp_keepalive(&keepalive)?;
    }

    Ok(())
}

pub fn set_common_sockopt_after_accept<S: AsRawSocket>(stream: &S, opts: &AcceptOpts) -> io::Result<()> {
    socket_call_warp(stream, |socket| set_common_sockopt_after_accept_impl(socket, opts))
}

fn set_common_sockopt_after_accept_impl(socket: &Socket, opts: &AcceptOpts) -> io::Result<()> {
    if let Some(buf_size) = opts.tcp.send_buffer_size {
        socket.set_send_buffer_size(buf_size as usize)?;
    }

    if let Some(buf_size) = opts.tcp.recv_buffer_size {
        socket.set_recv_buffer_size(buf_size as usize)?;
    }

    socket.set_tcp_nodelay(opts.tcp.nodelay)?;

    if let Some(intv) = opts.tcp.keepalive {
        let keepalive = TcpKeepalive::new().with_time(intv).with_interval(intv);
        socket.set_tcp_keepalive(&keepalive)?;
    }

    Ok(())
}
