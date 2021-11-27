use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use async_trait::async_trait;
use log::warn;
use shadowsocks::net::{is_dual_stack_addr, set_tcp_fastopen, AcceptOpts};
use socket2::Protocol;
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
            #[cfg(any(
                target_os = "openbsd",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "solaris",
                target_os = "macos",
                target_os = "ios",
            ))]
            RedirType::PacketFilter => {}

            #[cfg(any(
                target_os = "freebsd",
                target_os = "macos",
                target_os = "ios",
                target_os = "dragonfly"
            ))]
            RedirType::IpFirewall => {}

            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "not supported tcp transparent proxy type",
                ));
            }
        }

        // BSD platform doesn't have any special logic
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
}

impl TcpStreamRedirExt for TcpStream {
    fn destination_addr(&self, ty: RedirType) -> io::Result<SocketAddr> {
        match ty {
            #[cfg(any(
                target_os = "openbsd",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "solaris",
                target_os = "macos",
                target_os = "ios",
            ))]
            RedirType::PacketFilter => {
                use crate::local::redir::sys::bsd_pf::PF;

                let peer_addr = self.peer_addr()?;
                let bind_addr = self.local_addr()?;

                PF.natlook(&bind_addr, &peer_addr, Protocol::TCP)
            }
            #[cfg(any(
                target_os = "freebsd",
                target_os = "macos",
                target_os = "ios",
                target_os = "dragonfly"
            ))]
            RedirType::IpFirewall => {
                // ## IPFW
                //
                // For IPFW, uses getsockname() to retrieve destination address
                //
                // FreeBSD: https://www.freebsd.org/doc/handbook/firewalls-ipfw.html
                self.local_addr()
            }
            _ => unreachable!("not supported tcp transparent proxy type"),
        }
    }
}
