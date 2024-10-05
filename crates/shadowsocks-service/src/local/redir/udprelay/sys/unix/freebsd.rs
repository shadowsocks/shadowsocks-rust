use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, UdpSocket},
    os::unix::io::AsRawFd,
    ptr,
    task::{Context, Poll},
};

use futures::{future::poll_fn, ready};
use log::{error, trace, warn};
use shadowsocks::net::is_dual_stack_addr;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::{
    config::RedirType,
    local::redir::{
        redir_ext::{RedirSocketOpts, UdpSocketRedir},
        sys::set_ipv6_only,
    },
};

pub struct UdpRedirSocket {
    io: AsyncFd<UdpSocket>,
}

impl UdpRedirSocket {
    /// Create a new UDP socket binded to `addr`
    ///
    /// This will allow listening to `addr` that is not in local host
    pub fn listen(ty: RedirType, addr: SocketAddr) -> io::Result<UdpRedirSocket> {
        UdpRedirSocket::bind(ty, addr, false)
    }

    /// Create a new UDP socket binded to `addr`
    ///
    /// This will allow binding to `addr` that is not in local host
    pub fn bind_nonlocal(ty: RedirType, addr: SocketAddr, _: &RedirSocketOpts) -> io::Result<UdpRedirSocket> {
        UdpRedirSocket::bind(ty, addr, true)
    }

    fn bind(ty: RedirType, addr: SocketAddr, reuse_port: bool) -> io::Result<UdpRedirSocket> {
        if ty == RedirType::NotSupported {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "not supported udp transparent proxy type",
            ));
        }

        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        set_socket_before_bind(&addr, &socket)?;

        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        if reuse_port {
            if let Err(err) = socket.set_reuse_port(true) {
                if let Some(libc::ENOPROTOOPT) = err.raw_os_error() {
                    trace!("failed to set SO_REUSEPORT, error: {}", err);
                } else {
                    error!("failed to set SO_REUSEPORT, error: {}", err);
                    return Err(err);
                }
            }
        }

        let sock_addr = SockAddr::from(addr);

        if is_dual_stack_addr(&addr) {
            // set IP_ORIGDSTADDR before bind()

            // NOTE: FreeBSD doesn't allow setting IPPROTO_IP level on an IPv6 socket
            //
            // set_ip_origdstaddr(libc::IPPROTO_IP, &socket)?;
            // set_disable_ip_fragmentation(libc::IPPROTO_IP, &socket)?;

            match set_ipv6_only(&socket, false) {
                Ok(..) => {
                    if let Err(err) = socket.bind(&sock_addr) {
                        warn!(
                            "bind() dual-stack address {} failed, error: {}, fallback to IPV6_V6ONLY=true",
                            addr, err
                        );

                        if let Err(err) = set_ipv6_only(&socket, true) {
                            warn!(
                                "set IPV6_V6ONLY=true failed, error: {}, bind() to {} directly",
                                err, addr
                            );
                        }

                        socket.bind(&sock_addr)?;
                    }
                }
                Err(err) => {
                    warn!(
                        "set IPV6_V6ONLY=false failed, error: {}, bind() to {} directly",
                        err, addr
                    );
                    socket.bind(&sock_addr)?;
                }
            }
        } else {
            socket.bind(&sock_addr)?;
        }

        let io = AsyncFd::new(socket.into())?;
        Ok(UdpRedirSocket { io })
    }

    /// Send data to the socket to the given target address
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, buf, target)).await
    }

    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>> {
        loop {
            let mut write_guard = ready!(self.io.poll_write_ready(cx))?;

            match self.io.get_ref().send_to(buf, target) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    write_guard.clear_ready();
                }
                x => return Poll::Ready(x),
            }
        }
    }

    /// Returns the local address that this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }
}

impl UdpSocketRedir for UdpRedirSocket {
    fn poll_recv_dest_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr, SocketAddr)>> {
        loop {
            let mut read_guard = ready!(self.io.poll_read_ready(cx))?;

            match recv_dest_from(self.io.get_ref(), buf) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    read_guard.clear_ready();
                }
                x => return Poll::Ready(x),
            }
        }
    }
}

fn set_bindany(level: libc::c_int, socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;

    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE
    let opt = match level {
        libc::IPPROTO_IP => libc::IP_BINDANY,
        libc::IPPROTO_IPV6 => libc::IPV6_BINDANY,
        _ => unreachable!("level can only be IPPROTO_IP or IPPROTO_IPV6"),
    };

    unsafe {
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &enable as *const _ as *const _,
            mem::size_of_val(&enable) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

fn set_ip_origdstaddr(level: libc::c_int, socket: &Socket) -> io::Result<()> {
    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE

    let fd = socket.as_raw_fd();

    let enable: libc::c_int = 1;

    let opt = match level {
        libc::IPPROTO_IP => libc::IP_RECVORIGDSTADDR,
        libc::IPPROTO_IPV6 => libc::IPV6_RECVORIGDSTADDR,
        _ => unreachable!("level can only be IPPROTO_IP or IPPROTO_IPV6"),
    };

    unsafe {
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &enable as *const _ as *const _,
            mem::size_of_val(&enable) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

    Ok(())
}

fn set_disable_ip_fragmentation(level: libc::c_int, socket: &Socket) -> io::Result<()> {
    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE

    // sys/netinet/in.h
    // const IP_DONTFRAG: libc::c_int = 67; // don't fragment packet
    //
    // sys/netinet6/in6.h
    // const IPV6_DONTFRAG: libc::c_int = 62; // bool; disable IPv6 fragmentation

    let enable: libc::c_int = 1;

    let opt = match level {
        libc::IPPROTO_IP => libc::IP_DONTFRAG,
        libc::IPPROTO_IPV6 => libc::IPV6_DONTFRAG,
        _ => unreachable!("level can only be IPPROTO_IP or IPPROTO_IPV6"),
    };

    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            level,
            opt,
            &enable as *const _ as *const _,
            mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

fn set_socket_before_bind(addr: &SocketAddr, socket: &Socket) -> io::Result<()> {
    // https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+9.0-RELEASE
    let level = match *addr {
        SocketAddr::V4(..) => libc::IPPROTO_IP,
        SocketAddr::V6(..) => libc::IPPROTO_IPV6,
    };

    // 1. BINDANY
    set_bindany(level, socket)?;

    // 2. set ORIGDSTADDR for retrieving original destination address
    set_ip_origdstaddr(level, socket)?;

    // 3. disable IP fragmentation
    set_disable_ip_fragmentation(level, socket)?;

    Ok(())
}

fn get_destination_addr(msg: &libc::msghdr) -> io::Result<SocketAddr> {
    // https://www.freebsd.org/cgi/man.cgi?ip(4)
    //
    // Called `recvmsg` with `IP_ORIGDSTADDR` set

    unsafe {
        let (_, addr) = SockAddr::try_init(|dst_addr, dst_addr_len| {
            let mut cmsg: *mut libc::cmsghdr = libc::CMSG_FIRSTHDR(msg);
            while !cmsg.is_null() {
                let rcmsg = &*cmsg;
                match (rcmsg.cmsg_level, rcmsg.cmsg_type) {
                    (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR) => {
                        ptr::copy_nonoverlapping(
                            libc::CMSG_DATA(cmsg),
                            dst_addr as *mut _,
                            mem::size_of::<libc::sockaddr_in>(),
                        );
                        *dst_addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

                        return Ok(());
                    }
                    (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR) => {
                        ptr::copy_nonoverlapping(
                            libc::CMSG_DATA(cmsg),
                            dst_addr as *mut _,
                            mem::size_of::<libc::sockaddr_in6>(),
                        );
                        *dst_addr_len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

                        return Ok(());
                    }
                    _ => {}
                }
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
            }

            let err = Error::new(ErrorKind::InvalidData, "missing destination address in msghdr");
            Err(err)
        })?;

        Ok(addr.as_socket().expect("SocketAddr"))
    }
}

fn recv_dest_from(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut control_buf = [0u8; 64];
        let mut src_addr: libc::sockaddr_storage = mem::zeroed();

        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = &mut src_addr as *mut _ as *mut _;
        msg.msg_namelen = mem::size_of_val(&src_addr) as libc::socklen_t;

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len() as libc::size_t,
        };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        msg.msg_control = control_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = control_buf.len() as libc::socklen_t;

        let fd = socket.as_raw_fd();
        let ret = libc::recvmsg(fd, &mut msg, 0);
        if ret < 0 {
            return Err(Error::last_os_error());
        }

        let (_, src_saddr) = SockAddr::try_init(|a, l| {
            ptr::copy_nonoverlapping(msg.msg_name, a as *mut _, msg.msg_namelen as usize);
            *l = msg.msg_namelen;
            Ok(())
        })?;

        Ok((
            ret as usize,
            src_saddr.as_socket().expect("SocketAddr"),
            get_destination_addr(&msg)?,
        ))
    }
}
