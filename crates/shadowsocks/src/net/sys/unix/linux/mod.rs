use std::{
    io::{self, ErrorKind},
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    pin::Pin,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    task::{self, Poll},
};

use log::{debug, error, warn};
use pin_project::pin_project;
use socket2::{Domain, Protocol, SockAddr, SockAddrStorage, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};
use tokio_tfo::TfoStream;

use crate::net::{
    AcceptOpts, AddrFamily, ConnectOpts,
    sys::{set_common_sockopt_after_connect, set_common_sockopt_for_connect, socket_bind_dual_stack},
    udp::{BatchRecvMessage, BatchSendMessage},
};

/// A `TcpStream` that supports TFO (TCP Fast Open)
#[pin_project(project = TcpStreamProj)]
pub enum TcpStream {
    Standard(#[pin] TokioTcpStream),
    FastOpen(#[pin] TfoStream),
}

impl TcpStream {
    pub async fn connect(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<Self> {
        if opts.tcp.mptcp {
            return Self::connect_mptcp(addr, opts).await;
        }

        let socket = match addr {
            SocketAddr::V4(..) => TcpSocket::new_v4()?,
            SocketAddr::V6(..) => TcpSocket::new_v6()?,
        };

        Self::connect_with_socket(socket, addr, opts).await
    }

    async fn connect_mptcp(addr: SocketAddr, opts: &ConnectOpts) -> io::Result<Self> {
        let socket = create_mptcp_socket(&addr)?;
        Self::connect_with_socket(socket, addr, opts).await
    }

    async fn connect_with_socket(socket: TcpSocket, addr: SocketAddr, opts: &ConnectOpts) -> io::Result<Self> {
        // Any traffic to localhost should not be protected
        // This is a workaround for VPNService
        #[cfg(target_os = "android")]
        if !addr.ip().is_loopback() {
            android::vpn_protect(&socket, opts).await?;
        }

        // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
        // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
        if let Some(mark) = opts.fwmark {
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const _ as *const _,
                    mem::size_of_val(&mark) as libc::socklen_t,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                error!("set SO_MARK error: {}", err);
                return Err(err);
            }
        }

        // Set SO_BINDTODEVICE for binding to a specific interface
        if let Some(ref iface) = opts.bind_interface {
            set_bindtodevice(&socket, iface)?;
        }

        set_common_sockopt_for_connect(addr, &socket, opts)?;

        if !opts.tcp.fastopen {
            // If TFO is not enabled, it just works like a normal TcpStream
            let stream = socket.connect(addr).await?;
            set_common_sockopt_after_connect(&stream, opts)?;

            return Ok(Self::Standard(stream));
        }

        let stream = TfoStream::connect_with_socket(socket, addr).await?;
        set_common_sockopt_after_connect(&stream, opts)?;

        Ok(Self::FastOpen(stream))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            Self::Standard(ref s) => s.local_addr(),
            Self::FastOpen(ref s) => s.local_addr(),
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            Self::Standard(ref s) => s.peer_addr(),
            Self::FastOpen(ref s) => s.peer_addr(),
        }
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        match *self {
            Self::Standard(ref s) => s.nodelay(),
            Self::FastOpen(ref s) => s.nodelay(),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match *self {
            Self::Standard(ref s) => s.set_nodelay(nodelay),
            Self::FastOpen(ref s) => s.set_nodelay(nodelay),
        }
    }
}

impl AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        match *self {
            Self::Standard(ref s) => s.as_raw_fd(),
            Self::FastOpen(ref s) => s.as_raw_fd(),
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
/// `TCP_FASTOPEN` was supported since Linux 3.7
pub fn set_tcp_fastopen<S: AsRawFd>(socket: &S) -> io::Result<()> {
    // https://lwn.net/Articles/508865/
    //
    // The option value, qlen, specifies this server's limit on the size of the queue of TFO requests that have
    // not yet completed the three-way handshake (see the remarks on prevention of resource-exhaustion attacks above).
    //
    // It was recommended to be `5` in this document.
    //
    // But since mio's TcpListener sets backlogs to 1024, it would be nice to have 1024 slots for handshaking TFO requests.
    let queue: libc::c_int = 1024;

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &queue as *const _ as *const libc::c_void,
            mem::size_of_val(&queue) as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set TCP_FASTOPEN error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

fn create_mptcp_socket(bind_addr: &SocketAddr) -> io::Result<TcpSocket> {
    // https://www.kernel.org/doc/html/next/networking/mptcp.html

    unsafe {
        let family = match bind_addr {
            SocketAddr::V4(..) => libc::AF_INET,
            SocketAddr::V6(..) => libc::AF_INET6,
        };
        let fd = libc::socket(family, libc::SOCK_STREAM, libc::IPPROTO_MPTCP);
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(err);
        }
        let socket = Socket::from_raw_fd(fd);
        socket.set_nonblocking(true)?;
        Ok(TcpSocket::from_raw_fd(socket.into_raw_fd()))
    }
}

/// Create a TCP socket for listening
pub async fn create_inbound_tcp_socket(bind_addr: &SocketAddr, accept_opts: &AcceptOpts) -> io::Result<TcpSocket> {
    if accept_opts.tcp.mptcp {
        create_mptcp_socket(bind_addr)
    } else {
        match bind_addr {
            SocketAddr::V4(..) => TcpSocket::new_v4(),
            SocketAddr::V6(..) => TcpSocket::new_v6(),
        }
    }
}

/// Disable IP fragmentation
#[inline]
pub fn set_disable_ip_fragmentation<S: AsRawFd>(af: AddrFamily, socket: &S) -> io::Result<()> {
    // For Linux, IP_MTU_DISCOVER should be enabled for both IPv4 and IPv6 sockets
    // https://man7.org/linux/man-pages/man7/ip.7.html

    unsafe {
        let value: i32 = libc::IP_PMTUDISC_DO;
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &value as *const _ as *const _,
            mem::size_of_val(&value) as libc::socklen_t,
        );

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if af == AddrFamily::Ipv6 {
            let value: i32 = libc::IP_PMTUDISC_DO;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &value as *const _ as *const _,
                mem::size_of_val(&value) as libc::socklen_t,
            );

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

/// Create a `UdpSocket` with specific address family
#[inline]
pub async fn create_outbound_udp_socket(af: AddrFamily, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, config.bind_local_addr) {
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

    bind_outbound_udp_socket(&bind_addr, config).await
}

/// Create a `UdpSocket` binded to `bind_addr`
pub async fn bind_outbound_udp_socket(bind_addr: &SocketAddr, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let af = AddrFamily::from(bind_addr);

    let socket = if af != AddrFamily::Ipv6 {
        UdpSocket::bind(bind_addr).await?
    } else {
        let socket = Socket::new(Domain::for_address(*bind_addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket_bind_dual_stack(&socket, bind_addr, false)?;

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())?
    };

    if !config.udp.allow_fragmentation {
        if let Err(err) = set_disable_ip_fragmentation(af, &socket) {
            warn!("failed to disable IP fragmentation, error: {}", err);
        }
    }

    // Any traffic except localhost should be protected
    // This is a workaround for VPNService
    #[cfg(target_os = "android")]
    android::vpn_protect(&socket, config).await?;

    // Set SO_MARK for mark-based routing on Linux (since 2.6.25)
    // NOTE: This will require CAP_NET_ADMIN capability (root in most cases)
    if let Some(mark) = config.fwmark {
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const _ as *const _,
                mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_MARK error: {}", err);
            return Err(err);
        }
    }

    // Set SO_BINDTODEVICE for binding to a specific interface
    if let Some(ref iface) = config.bind_interface {
        set_bindtodevice(&socket, iface)?;
    }

    Ok(socket)
}

fn set_bindtodevice<S: AsRawFd>(socket: &S, iface: &str) -> io::Result<()> {
    let iface_bytes = iface.as_bytes();

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_bytes.as_ptr() as *const _ as *const libc::c_void,
            iface_bytes.len() as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
            error!("set SO_BINDTODEVICE error: {}", err);
            return Err(err);
        }
    }

    Ok(())
}

#[cfg(target_os = "android")]
mod android {
    use std::{
        io::{self, ErrorKind},
        os::unix::io::{AsRawFd, RawFd},
        path::Path,
        time::Duration,
    };
    use tokio::{io::AsyncReadExt, time};

    use super::super::uds::UnixStream;
    use super::ConnectOpts;

    /// This is a RPC for Android to `protect()` socket for connecting to remote servers
    ///
    /// https://developer.android.com/reference/android/net/VpnService#protect(java.net.Socket)
    ///
    /// More detail could be found in [shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android) project.
    async fn send_vpn_protect_uds<P: AsRef<Path>>(protect_path: P, fd: RawFd) -> io::Result<()> {
        let mut stream = UnixStream::connect(protect_path).await?;

        // send fds
        let dummy: [u8; 1] = [1];
        let fds: [RawFd; 1] = [fd];
        stream.send_with_fd(&dummy, &fds).await?;

        // receive the return value
        let mut response = [0; 1];
        stream.read_exact(&mut response).await?;

        if response[0] == 0xFF {
            return Err(io::Error::other("protect() failed"));
        }

        Ok(())
    }

    /// Try to run VPNService#protect on Android
    ///
    /// https://developer.android.com/reference/android/net/VpnService#protect(java.net.Socket)
    pub async fn vpn_protect<S>(socket: &S, opts: &ConnectOpts) -> io::Result<()>
    where
        S: AsRawFd + Send + Sync + 'static,
    {
        // shadowsocks-android uses a Unix domain socket to communicate with the VPNService#protect
        if let Some(ref path) = opts.vpn_protect_path {
            // RPC calls to `VpnService.protect()`
            // Timeout in 3 seconds like shadowsocks-libev
            match time::timeout(Duration::from_secs(3), send_vpn_protect_uds(path, socket.as_raw_fd())).await {
                Ok(Ok(..)) => {}
                Ok(Err(err)) => return Err(err),
                Err(..) => return Err(io::Error::new(ErrorKind::TimedOut, "protect() timeout")),
            }
        }

        // Customized SocketProtect
        if let Some(ref protect) = opts.vpn_socket_protect {
            protect.protect(socket.as_raw_fd())?;
        }

        Ok(())
    }
}

static SUPPORT_BATCH_SEND_RECV_MSG: AtomicBool = AtomicBool::new(true);

fn recvmsg_fallback<S: AsRawFd>(sock: &S, msg: &mut BatchRecvMessage<'_>) -> io::Result<()> {
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };

    let addr_storage = SockAddrStorage::zeroed();
    let addr_len = addr_storage.size_of() as libc::socklen_t;

    let sock_addr = unsafe { SockAddr::new(addr_storage, addr_len) };
    hdr.msg_name = sock_addr.as_ptr() as *mut _;
    hdr.msg_namelen = sock_addr.len() as _;

    hdr.msg_iov = msg.data.as_ptr() as *mut _;
    hdr.msg_iovlen = msg.data.len() as _;

    let ret = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut hdr as *mut _, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    msg.addr = sock_addr.as_socket().expect("SockAddr.as_socket");
    msg.data_len = ret as usize;

    Ok(())
}

pub fn batch_recvmsg<S: AsRawFd>(sock: &S, msgs: &mut [BatchRecvMessage<'_>]) -> io::Result<usize> {
    if msgs.is_empty() {
        return Ok(0);
    }

    if !SUPPORT_BATCH_SEND_RECV_MSG.load(Ordering::Relaxed) {
        recvmsg_fallback(sock, &mut msgs[0])?;
        return Ok(1);
    }

    let mut vec_msg_name = Vec::with_capacity(msgs.len());
    let mut vec_msg_hdr = Vec::with_capacity(msgs.len());

    for msg in msgs.iter_mut() {
        let mut hdr: libc::mmsghdr = unsafe { mem::zeroed() };

        let addr_storage = SockAddrStorage::zeroed();
        let addr_len = addr_storage.size_of() as libc::socklen_t;

        vec_msg_name.push(unsafe { SockAddr::new(addr_storage, addr_len) });
        let sock_addr = vec_msg_name.last_mut().unwrap();
        hdr.msg_hdr.msg_name = sock_addr.as_ptr() as *mut _;
        hdr.msg_hdr.msg_namelen = sock_addr.len() as _;

        hdr.msg_hdr.msg_iov = msg.data.as_ptr() as *mut _;
        hdr.msg_hdr.msg_iovlen = msg.data.len() as _;

        vec_msg_hdr.push(hdr);
    }

    let ret = unsafe {
        libc::recvmmsg(
            sock.as_raw_fd(),
            vec_msg_hdr.as_mut_ptr(),
            vec_msg_hdr.len() as _,
            0,
            ptr::null_mut(),
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if let Some(libc::ENOSYS) = err.raw_os_error() {
            debug!("recvmmsg is not supported, fallback to recvmsg, error: {:?}", err);
            SUPPORT_BATCH_SEND_RECV_MSG.store(false, Ordering::Relaxed);

            recvmsg_fallback(sock, &mut msgs[0])?;
            return Ok(1);
        }
        return Err(err);
    }

    for idx in 0..ret as usize {
        let msg = &mut msgs[idx];
        let hdr = &vec_msg_hdr[idx];
        let name = &vec_msg_name[idx];
        msg.addr = name.as_socket().expect("SockAddr.as_socket");
        msg.data_len = hdr.msg_len as usize;
    }

    Ok(ret as usize)
}

fn sendmsg_fallback<S: AsRawFd>(sock: &S, msg: &mut BatchSendMessage<'_>) -> io::Result<()> {
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };

    let sock_addr = msg.addr.map(SockAddr::from);
    if let Some(ref sa) = sock_addr {
        hdr.msg_name = sa.as_ptr() as *mut _;
        hdr.msg_namelen = sa.len() as _;
    }

    hdr.msg_iov = msg.data.as_ptr() as *mut _;
    hdr.msg_iovlen = msg.data.len() as _;

    let ret = unsafe { libc::sendmsg(sock.as_raw_fd(), &hdr as *const _, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    msg.data_len = ret as usize;

    Ok(())
}

pub fn batch_sendmsg<S: AsRawFd>(sock: &S, msgs: &mut [BatchSendMessage<'_>]) -> io::Result<usize> {
    if msgs.is_empty() {
        return Ok(0);
    }

    if !SUPPORT_BATCH_SEND_RECV_MSG.load(Ordering::Relaxed) {
        sendmsg_fallback(sock, &mut msgs[0])?;
        return Ok(1);
    }

    let mut vec_msg_name = Vec::with_capacity(msgs.len());
    let mut vec_msg_hdr = Vec::with_capacity(msgs.len());

    for msg in msgs.iter_mut() {
        let mut hdr: libc::mmsghdr = unsafe { mem::zeroed() };

        if let Some(addr) = msg.addr {
            vec_msg_name.push(SockAddr::from(addr));
            let sock_addr = vec_msg_name.last_mut().unwrap();
            hdr.msg_hdr.msg_name = sock_addr.as_ptr() as *mut _;
            hdr.msg_hdr.msg_namelen = sock_addr.len() as _;
        }

        hdr.msg_hdr.msg_iov = msg.data.as_ptr() as *mut _;
        hdr.msg_hdr.msg_iovlen = msg.data.len() as _;

        vec_msg_hdr.push(hdr);
    }

    let ret = unsafe { libc::sendmmsg(sock.as_raw_fd(), vec_msg_hdr.as_mut_ptr(), vec_msg_hdr.len() as _, 0) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if let Some(libc::ENOSYS) = err.raw_os_error() {
            debug!("sendmmsg is not supported, fallback to sendmsg, error: {:?}", err);
            SUPPORT_BATCH_SEND_RECV_MSG.store(false, Ordering::Relaxed);

            sendmsg_fallback(sock, &mut msgs[0])?;
            return Ok(1);
        }
        return Err(err);
    }

    for idx in 0..ret as usize {
        let msg = &mut msgs[idx];
        let hdr = &vec_msg_hdr[idx];
        msg.data_len = hdr.msg_len as usize;
    }

    Ok(ret as usize)
}
