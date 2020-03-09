use std::{
    io::{self, Error, ErrorKind},
    mem,
    net::SocketAddr,
    os::unix::io::AsRawFd,
};

use async_trait::async_trait;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    config::RedirType,
    relay::{redir::TcpListenerRedirExt, sys::sockaddr_to_std},
};

pub struct TcpRedirListener {
    l: TcpListener,
    ty: RedirType,
}

impl TcpRedirListener {
    /// Create a TCP listener binding to `addr` and enable transparent proxy feature
    pub async fn bind(ty: RedirType, addr: &SocketAddr) -> io::Result<TcpRedirListener> {
        let l = match ty {
            RedirType::Netfilter => {
                // REDIRECT rule doesn't need to set IP_TRANSPARENT
                TcpListener::bind(addr).await?
            }
            RedirType::TProxy => {
                // TPROXY rule requires IP_TRANSPARENT
                create_redir_listener(addr)?
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "not supported tcp transparent proxy type",
                ));
            }
        };

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
        let (mut socket, src_addr) = self.l.accept().await?;

        let dst_addr = match self.ty {
            RedirType::Netfilter => get_original_destination_addr(&mut socket)?,
            RedirType::TProxy => {
                // For TPROXY, uses getsockname() to retrieve original destination address
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

fn get_original_destination_addr(s: &mut TcpStream) -> io::Result<Option<SocketAddr>> {
    let fd = s.as_raw_fd();

    unsafe {
        let mut target_addr: libc::sockaddr_storage = mem::zeroed();
        let mut target_addr_len = mem::size_of_val(&target_addr) as libc::socklen_t;

        // Check if it is IPv6 address
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            libc::SO_ORIGINAL_DST, // FIXME: Should use IP6T_SO_ORIGINAL_DST
            &mut target_addr as *mut _ as *mut _,
            &mut target_addr_len,
        );

        if ret != 0 {
            let err = Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP) => {
                    // The option is unknown at the level indicated.
                    //
                    // - The current system doesn't support IPv6 netfilter
                    // - This is not an IPv6 connection
                    //
                    // Continue with IPv4
                }
                _ => {
                    return Err(err);
                }
            }

            let ret = libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut target_addr as *mut _ as *mut _,
                &mut target_addr_len,
            );

            if ret != 0 {
                let err = Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EOPNOTSUPP) => {
                        return Ok(None);
                    }
                    _ => {
                        return Err(err);
                    }
                }
            }
        }

        // Convert sockaddr_storage to SocketAddr
        sockaddr_to_std(&target_addr).map(Some)
    }
}

fn create_redir_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let domain = match *addr {
        SocketAddr::V4(..) => Domain::ipv4(),
        SocketAddr::V6(..) => Domain::ipv6(),
    };

    let socket = Socket::new(domain, Type::stream(), Some(Protocol::tcp()))?;

    // For Linux 2.4+ TPROXY
    // Sockets have to set IP_TRANSPARENT for retrieving original destination by getsockname()
    unsafe {
        let fd = socket.as_raw_fd();

        let enable: libc::c_int = 1;
        let ret = match *addr {
            SocketAddr::V4(..) => libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
            SocketAddr::V6(..) => libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP_TRANSPARENT,
                &enable as *const _ as *const _,
                mem::size_of_val(&enable) as libc::socklen_t,
            ),
        };

        if ret != 0 {
            return Err(Error::last_os_error());
        }
    }

    // tokio requires non-blocked socket, and allow reuse addr
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    let addr = SockAddr::from(*addr);

    // bind, listen as original
    socket.bind(&addr)?;
    socket.listen(1024)?; // backlogs = 1024 as mio's default

    TcpListener::from_std(socket.into_tcp_listener())
}
