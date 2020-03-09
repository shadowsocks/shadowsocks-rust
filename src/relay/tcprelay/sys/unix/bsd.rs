use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use async_trait::async_trait;
use socket2::Protocol;
use tokio::net::{TcpListener, TcpStream};

use crate::{config::RedirType, relay::redir::TcpListenerRedirExt};

pub struct TcpRedirListener {
    l: TcpListener,
    ty: RedirType,
}

impl TcpRedirListener {
    /// Create a TCP listener binding to `addr` and enable transparent proxy feature
    pub async fn bind(ty: RedirType, addr: &SocketAddr) -> io::Result<TcpRedirListener> {
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
                    "not supported tcp transparent proxy",
                ));
            }
        }

        let l = TcpListener::bind(addr).await?;
        Ok(TcpRedirListener { l, ty })
    }

    /// Get local bind addr for TcpListener
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.l.local_addr()
    }
}

#[async_trait]
impl TcpListenerRedirExt for TcpRedirListener {
    async fn accept_redir(&mut self) -> io::Result<(TcpStream, SocketAddr, Option<SocketAddr>)> {
        let (socket, src_addr) = self.l.accept().await?;

        let dst_addr = match self.ty {
            #[cfg(any(
                target_os = "openbsd",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "solaris",
                target_os = "macos",
                target_os = "ios",
            ))]
            RedirType::PacketFilter => {
                use crate::relay::sys::bsd_pf::PF;

                let bind_addr = socket.local_addr()?;
                PF.natlook(&bind_addr, &src_addr, Protocol::tcp())?
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
                Some(socket.local_addr()?)
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "not supported tcp transparent proxy type",
                ));
            }
        };

        Ok((socket, src_addr, dst_addr))
    }
}
