use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use log::warn;
use shadowsocks::net::{AcceptOpts, is_dual_stack_addr, set_tcp_fastopen};
use socket2::Protocol;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::{
    config::RedirType,
    local::redir::{
        redir_ext::{TcpListenerRedirExt, TcpStreamRedirExt},
        sys::set_ipv6_only,
    },
};

impl TcpListenerRedirExt for TcpListener {
    async fn bind_redir(ty: RedirType, addr: SocketAddr, accept_opts: AcceptOpts) -> io::Result<TcpListener> {
        match ty {
            #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "macos", target_os = "ios"))]
            RedirType::PacketFilter => {}

            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
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
            // Try to bind dual-stack address
            match set_ipv6_only(&socket, false) {
                Ok(..) => {
                    // bind()
                    if let Err(err) = socket.bind(addr) {
                        warn!(
                            "bind() dual-stack address {} failed, error: {}, fallback to IPV6_V6ONLY=false",
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
            socket.bind(addr)?;
        }

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
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
            RedirType::PacketFilter => {
                use crate::local::redir::sys::bsd_pf::PF;

                let peer_addr = self.peer_addr()?;
                let bind_addr = self.local_addr()?;

                PF.natlook(&bind_addr, &peer_addr, Protocol::TCP)
            }
            #[cfg(target_os = "openbsd")] // in OpenBSD, we can get TCP destination address with getsockname()
            RedirType::PacketFilter => self.local_addr(),
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
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
