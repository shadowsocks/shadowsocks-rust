use std::{
    io::{self, ErrorKind},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
            set_ip_bound_if(&socket, addr, iface)?;
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
/// `TCP_FASTOPEN` was supported since
/// macosx(10.11), ios(9.0), tvos(9.0), watchos(2.0)
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

fn set_ip_bound_if<S: AsRawFd>(socket: &S, addr: SocketAddr, iface: &str) -> io::Result<()> {
    const IP_BOUND_IF: libc::c_int = 25; // bsd/netinet/in.h
    const IPV6_BOUND_IF: libc::c_int = 125; // bsd/netinet6/in6.h

    unsafe {
        let mut ciface = [0u8; libc::IFNAMSIZ];
        if iface.len() >= ciface.len() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let iface_bytes = iface.as_bytes();
        ptr::copy_nonoverlapping(iface_bytes.as_ptr(), ciface.as_mut_ptr(), iface_bytes.len());

        let index = libc::if_nametoindex(ciface.as_ptr() as *const libc::c_char);
        if index == 0 {
            let err = io::Error::last_os_error();
            error!("if_nametoindex ifname: {} error: {}", iface, err);
            return Err(err);
        }

        let ret = match addr {
            SocketAddr::V4(..) => libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_BOUND_IF,
                &index as *const _ as *const _,
                mem::size_of_val(&index) as libc::socklen_t,
            ),
            SocketAddr::V6(..) => libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_BOUND_IF,
                &index as *const _ as *const _,
                mem::size_of_val(&index) as libc::socklen_t,
            ),
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            error!(
                "set IF_BOUND_IF/IPV6_BOUND_IF ifname: {} ifindex: {} error: {}",
                iface, index, err
            );
            return Err(err);
        }
    }

    Ok(())
}

/// Disable IP fragmentation
#[inline]
pub fn set_disable_ip_fragmentation<S: AsRawFd>(af: AddrFamily, socket: &S) -> io::Result<()> {
    unsafe {
        match af {
            AddrFamily::Ipv4 => {
                let enable: i32 = 1;
                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_DONTFRAG,
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
                    libc::IPV6_DONTFRAG,
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

/// Create a `UdpSocket` for connecting to `addr`
pub async fn create_outbound_udp_socket(af: AddrFamily, config: &ConnectOpts) -> io::Result<UdpSocket> {
    let bind_addr = match (af, config.bind_local_addr) {
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

    // Set IP_BOUND_IF for BSD-like
    if let Some(ref iface) = config.bind_interface {
        set_ip_bound_if(&socket, bind_addr, iface)?;
    }

    Ok(socket)
}

/// https://github.com/apple/darwin-xnu/blob/main/bsd/sys/socket.h
#[repr(C)]
struct msghdr_x {
    msg_name: *mut libc::c_void,     //< optional address
    msg_namelen: libc::socklen_t,    //< size of address
    msg_iov: *mut libc::iovec,       //< scatter/gather array
    msg_iovlen: libc::c_int,         //< # elements in msg_iov
    msg_control: *mut libc::c_void,  //< ancillary data, see below
    msg_controllen: libc::socklen_t, //< ancillary data buffer len
    msg_flags: libc::c_int,          //< flags on received message
    msg_datalen: libc::size_t,       //< byte length of buffer in msg_iov
}

extern "C" {
    fn recvmsg_x(s: libc::c_int, msgp: *const msghdr_x, cnt: libc::c_uint, flags: libc::c_int) -> libc::ssize_t;
    fn sendmsg_x(s: libc::c_int, msgp: *const msghdr_x, cnt: libc::c_uint, flags: libc::c_int) -> libc::ssize_t;
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

    if !SUPPORT_BATCH_SEND_RECV_MSG.load(Ordering::Acquire) {
        recvmsg_fallback(sock, &mut msgs[0])?;
        return Ok(1);
    }

    let mut vec_msg_name = Vec::with_capacity(msgs.len());
    let mut vec_msg_hdr = Vec::with_capacity(msgs.len());

    for msg in msgs.iter_mut() {
        let mut hdr: msghdr_x = unsafe { mem::zeroed() };

        let addr_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let addr_len = mem::size_of_val(&addr_storage) as libc::socklen_t;

        vec_msg_name.push(unsafe { SockAddr::new(addr_storage, addr_len) });
        let sock_addr = vec_msg_name.last_mut().unwrap();
        hdr.msg_name = sock_addr.as_ptr() as *mut _;
        hdr.msg_namelen = sock_addr.len() as _;

        hdr.msg_iov = msg.data.as_ptr() as *mut _;
        hdr.msg_iovlen = msg.data.len() as _;

        vec_msg_hdr.push(hdr);
    }

    let ret = unsafe { recvmsg_x(sock.as_raw_fd(), vec_msg_hdr.as_ptr(), vec_msg_hdr.len() as _, 0) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if let Some(libc::ENOSYS) = err.raw_os_error() {
            debug!("recvmsg_x is not supported, fallback to recvmsg, error: {:?}", err);
            SUPPORT_BATCH_SEND_RECV_MSG.store(false, Ordering::Release);

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
        msg.data_len = hdr.msg_datalen;
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

    if !SUPPORT_BATCH_SEND_RECV_MSG.load(Ordering::Acquire) {
        sendmsg_fallback(sock, &mut msgs[0])?;
        return Ok(1);
    }

    let mut vec_msg_name = Vec::with_capacity(msgs.len());
    let mut vec_msg_hdr = Vec::with_capacity(msgs.len());

    for msg in msgs.iter_mut() {
        let mut hdr: msghdr_x = unsafe { mem::zeroed() };

        if let Some(addr) = msg.addr {
            vec_msg_name.push(SockAddr::from(addr));
            let sock_addr = vec_msg_name.last_mut().unwrap();
            hdr.msg_name = sock_addr.as_ptr() as *mut _;
            hdr.msg_namelen = sock_addr.len() as _;
        }

        hdr.msg_iov = msg.data.as_ptr() as *mut _;
        hdr.msg_iovlen = msg.data.len() as _;

        vec_msg_hdr.push(hdr);
    }

    let ret = unsafe { sendmsg_x(sock.as_raw_fd(), vec_msg_hdr.as_ptr(), vec_msg_hdr.len() as _, 0) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if let Some(libc::ENOSYS) = err.raw_os_error() {
            debug!("sendmsg_x is not supported, fallback to sendmsg, error: {:?}", err);
            SUPPORT_BATCH_SEND_RECV_MSG.store(false, Ordering::Release);

            sendmsg_fallback(sock, &mut msgs[0])?;
            return Ok(1);
        }
        return Err(err);
    }

    for idx in 0..ret as usize {
        let msg = &mut msgs[idx];
        let hdr = &vec_msg_hdr[idx];
        msg.data_len = hdr.msg_datalen;
    }

    Ok(ret as usize)
}
