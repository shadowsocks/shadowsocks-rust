use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
};

use log::warn;
use shadowsocks::net::{AcceptOpts, is_dual_stack_addr, set_tcp_fastopen};
use socket2::SockAddr;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::{
    config::RedirType,
    local::redir::{
        redir_ext::{TcpListenerRedirExt, TcpStreamRedirExt},
        sys::set_ipv6_only,
    },
};

impl TcpListenerRedirExt for TcpListener {
    async fn bind_redir(ty: RedirType, addr: SocketAddr, accept_opts: AcceptOpts) -> io::Result<Self> {
        match ty {
            RedirType::Redirect => {
                // REDIRECT rule doesn't need to set IP_TRANSPARENT

                let socket = match addr {
                    SocketAddr::V4(..) => TcpSocket::new_v4()?,
                    SocketAddr::V6(..) => TcpSocket::new_v6()?,
                };

                // On platforms with Berkeley-derived sockets, this allows to quickly
                // rebind a socket, without needing to wait for the OS to clean up the
                // previous one.
                //
                // On Windows, this allows rebinding sockets which are actively in use,
                // which allows “socket hijacking”, so we explicitly don't set it here.
                // https://docs.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
                #[cfg(unix)]
                socket.set_reuseaddr(true)?;

                let set_dual_stack = is_dual_stack_addr(&addr);
                if set_dual_stack {
                    // Try to bind dual-stack address
                    match set_ipv6_only(&socket, false) {
                        Ok(..) => {
                            // bind()
                            if let Err(err) = socket.bind(addr) {
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

                                socket.bind(addr)?;
                            }
                        }
                        Err(err) => {
                            warn!(
                                "set IPV6_V6ONLY=false failed, error: {}, bind() to {} directly",
                                err, addr
                            );
                            socket.bind(addr)?;
                        }
                    }
                } else {
                    // bind, listen as original
                    socket.bind(addr)?;
                }

                // mio's default backlog is 1024
                let listener = socket.listen(1024)?;

                if accept_opts.tcp.fastopen {
                    set_tcp_fastopen(&listener)?;
                }

                Ok(listener)
            }
            RedirType::TProxy => {
                // TPROXY rule requires IP_TRANSPARENT
                create_redir_listener(addr, accept_opts).await
            }
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                "not supported tcp transparent proxy type",
            )),
        }
    }
}

impl TcpStreamRedirExt for TcpStream {
    fn destination_addr(&self, ty: RedirType) -> io::Result<SocketAddr> {
        match ty {
            RedirType::Redirect => get_original_destination_addr(self),
            RedirType::TProxy => {
                // For TPROXY, uses getsockname() to retrieve original destination address
                self.local_addr()
            }
            _ => unreachable!("not supported tcp transparent proxy type"),
        }
    }
}

fn get_original_destination_addr(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    unsafe {
        let (_, target_addr) = SockAddr::try_init(|target_addr, target_addr_len| {
            // No sufficient method to know whether the destination IPv4 or IPv6.
            // Follow the method in shadowsocks-libev.

            let ret = libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP6T_SO_ORIGINAL_DST,
                target_addr as *mut _,
                target_addr_len, // libc::socklen_t
            );

            if ret == 0 {
                return Ok(());
            } else {
                let err = Error::last_os_error();
                match err.raw_os_error() {
                    None => return Err(err),
                    // ENOPROTOOPT, EOPNOTSUPP (ENOTSUP): IP6T_SO_ORIGINAL_DST doesn't exist
                    // ENOENT: Destination address is not IPv6
                    #[allow(unreachable_patterns)]
                    Some(libc::ENOPROTOOPT) | Some(libc::ENOENT) | Some(libc::EOPNOTSUPP) | Some(libc::ENOTSUP) => {}
                    Some(..) => return Err(err),
                }
            }

            let ret = libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                target_addr as *mut _,
                target_addr_len, // libc::socklen_t
            );

            if ret != 0 {
                let err = Error::last_os_error();
                return Err(err);
            }

            Ok(())
        })?;

        // Convert sockaddr_storage to SocketAddr
        Ok(target_addr.as_socket().expect("SocketAddr"))
    }
}

fn set_ip_transparent(level: libc::c_int, socket: &TcpSocket) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let opt = match level {
        libc::IPPROTO_IP => libc::IP_TRANSPARENT,
        libc::IPPROTO_IPV6 => libc::IPV6_TRANSPARENT,
        _ => unreachable!("level can only be IPPROTO_IP and IPPROTO_IPV6"),
    };

    let enable: libc::c_int = 1;

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

async fn create_redir_listener(addr: SocketAddr, accept_opts: AcceptOpts) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    // For Linux 2.4+ TPROXY
    // Sockets have to set IP_TRANSPARENT, IPV6_TRANSPARENT for retrieving original destination by getsockname()
    let level = match addr {
        SocketAddr::V4(..) => libc::IPPROTO_IP,
        SocketAddr::V6(..) => libc::IPPROTO_IPV6,
    };

    set_ip_transparent(level, &socket)?;

    // On platforms with Berkeley-derived sockets, this allows to quickly
    // rebind a socket, without needing to wait for the OS to clean up the
    // previous one.
    //
    // On Windows, this allows rebinding sockets which are actively in use,
    // which allows “socket hijacking”, so we explicitly don't set it here.
    // https://docs.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;

    let set_dual_stack = is_dual_stack_addr(&addr);
    if set_dual_stack {
        // set IP_TRANSPARENT before bind()
        set_ip_transparent(libc::IPPROTO_IP, &socket)?;

        // Try to bind dual-stack address
        match set_ipv6_only(&socket, false) {
            Ok(..) => {
                // bind()
                if let Err(err) = socket.bind(addr) {
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

                    socket.bind(addr)?;
                }
            }
            Err(err) => {
                warn!(
                    "set IPV6_V6ONLY=false failed, error: {}, bind() to {} directly",
                    err, addr
                );
                socket.bind(addr)?;
            }
        }
    } else {
        // bind, listen as original
        socket.bind(addr)?;
    }

    // listen backlogs = 1024 as mio's default
    let listener = socket.listen(1024)?;

    if accept_opts.tcp.fastopen {
        set_tcp_fastopen(&listener)?;
    }

    Ok(listener)
}
