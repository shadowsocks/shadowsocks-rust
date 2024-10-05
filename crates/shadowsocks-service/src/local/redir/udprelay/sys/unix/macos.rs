use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::{SocketAddr, UdpSocket},
    os::unix::io::AsRawFd,
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
        sys::{bsd_pf::PF, set_ipv6_only},
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

            let (n, peer_addr) = match self.io.get_ref().recv_from(buf) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    read_guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e).into(),
                Ok(x) => x,
            };

            let bind_addr = self.local_addr()?;
            let actual_addr = PF.natlook(&bind_addr, &peer_addr, Protocol::UDP)?;

            return Ok((n, peer_addr, actual_addr)).into();
        }
    }
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

    // 1. disable IP fragmentation
    set_disable_ip_fragmentation(level, socket)?;

    Ok(())
}
