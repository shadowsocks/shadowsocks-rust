use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
};

use async_trait::async_trait;
use log::warn;
use shadowsocks::net::{is_dual_stack_addr, set_tcp_fastopen, AcceptOpts};
use socket2::SockAddr;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::{
    config::RedirType,
    local::redir::{
        redir_ext::{TcpListenerRedirExt, TcpStreamRedirExt},
        sys::set_ipv6_only,
    },
};

#[async_trait]
impl TcpListenerRedirExt for TcpListener {
    async fn bind_redir(ty: RedirType, addr: SocketAddr, accept_opts: AcceptOpts) -> io::Result<TcpListener> {
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
                    // Transparent socket shouldn't support dual-stack.

                    if let Err(err) = set_ipv6_only(&socket, true) {
                        warn!("failed to set IPV6_V6ONLY, error: {}", err);
                    }
                }

                socket.bind(addr)?;

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
        let (_, target_addr) = SockAddr::init(|target_addr, target_addr_len| {
            match s.local_addr()? {
                SocketAddr::V4(..) => {
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
                }
                SocketAddr::V6(..) => {
                    let ret = libc::getsockopt(
                        fd,
                        libc::SOL_IPV6,
                        libc::IP6T_SO_ORIGINAL_DST,
                        target_addr as *mut _,
                        target_addr_len, // libc::socklen_t
                    );

                    if ret != 0 {
                        let err = Error::last_os_error();
                        return Err(err);
                    }
                }
            }
            Ok(())
        })?;

        // Convert sockaddr_storage to SocketAddr
        Ok(target_addr.as_socket().expect("SocketAddr"))
    }
}

async fn create_redir_listener(addr: SocketAddr, accept_opts: AcceptOpts) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    // For Linux 2.4+ TPROXY
    // Sockets have to set IP_TRANSPARENT, IPV6_TRANSPARENT for retrieving original destination by getsockname()
    unsafe {
        let fd = socket.as_raw_fd();

        let enable: libc::c_int = 1;
        let ret = match addr {
            SocketAddr::V4(..) => libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
            SocketAddr::V6(..) => libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
        };

        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

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
        // Transparent socket shouldn't support dual-stack.

        if let Err(err) = set_ipv6_only(&socket, true) {
            warn!("failed to set IPV6_V6ONLY, error: {}", err);
        }
    }

    // bind, listen as original
    socket.bind(addr)?;

    // listen backlogs = 1024 as mio's default
    let listener = socket.listen(1024)?;

    if accept_opts.tcp.fastopen {
        set_tcp_fastopen(&listener)?;
    }

    Ok(listener)
}
