use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    task::{self, Poll},
};

use log::{debug, error, warn};
use pin_project::pin_project;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpSocket, TcpStream as TokioTcpStream, UdpSocket},
};
use tokio_tfo::TfoStream;

use crate::net::{
    sys::{set_common_sockopt_after_connect, set_common_sockopt_for_connect, socket_bind_dual_stack},
    udp::{BatchRecvMessage, BatchSendMessage},
    AcceptOpts, AddrFamily, ConnectOpts,
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

        // Set SO_USER_COOKIE for mark-based routing on FreeBSD
        if let Some(user_cookie) = opts.user_cookie {
            let ret = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_USER_COOKIE,
                    &user_cookie as *const _ as *const _,
                    mem::size_of_val(&user_cookie) as libc::socklen_t,
                )
            };
            if ret != 0 {
                let err = io::Error::last_os_error();
                error!("set SO_USER_COOKIE error: {}", err);
                return Err(err);
            }
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

impl AsRawFd for TcpStream {
    fn as_raw_fd(&self) -> RawFd {
        match *self {
            TcpStream::Standard(ref s) => s.as_raw_fd(),
            TcpStream::FastOpen(ref s) => s.as_raw_fd(),
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
/// TCP_FASTOPEN was supported since FreeBSD 12.0
///
/// Example program: <https://people.freebsd.org/~pkelsey/tfo-tools/tfo-srv.c>
pub fn set_tcp_fastopen<S: AsRawFd>(socket: &S) -> io::Result<()> {
    let enable: libc::c_int = 1;

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &enable as *const _ as *const libc::c_void,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            let err = io::Error::last_os_error();
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

/// Disable IP fragmentation
#[inline]
pub fn set_disable_ip_fragmentation<S: AsRawFd>(af: AddrFamily, socket: &S) -> io::Result<()> {
    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE

    // sys/netinet/in.h
    const IP_DONTFRAG: libc::c_int = 67; // don't fragment packet

    // sys/netinet6/in6.h
    const IPV6_DONTFRAG: libc::c_int = 62; // bool; disable IPv6 fragmentation

    unsafe {
        match af {
            AddrFamily::Ipv4 => {
                let enable: i32 = 1;
                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    IP_DONTFRAG,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                );

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            AddrFamily::Ipv6 => {
                let enable: i32 = 1;
                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    IPV6_DONTFRAG,
                    &enable as *const _ as *const _,
                    mem::size_of_val(&enable) as libc::socklen_t,
                );

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
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
        (AddrFamily::Ipv6, Some(SocketAddr::V6(addr))) => addr.into(),
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

    Ok(socket)
}

static SUPPORT_BATCH_SEND_RECV_MSG: AtomicBool = AtomicBool::new(true);

fn recvmsg_fallback<S: AsRawFd>(sock: &S, msg: &mut BatchRecvMessage<'_>) -> io::Result<()> {
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };

    let addr_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let addr_len = mem::size_of_val(&addr_storage) as libc::socklen_t;
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

        let addr_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let addr_len = mem::size_of_val(&addr_storage) as libc::socklen_t;

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
            ptr::null(),
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
