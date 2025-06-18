//! Network wrappers for shadowsocks' specific requirements

use std::net::SocketAddr;

#[cfg(unix)]
pub use self::sys::uds::{UnixListener, UnixStream};
pub use self::{
    option::{AcceptOpts, ConnectOpts, TcpSocketOpts, UdpSocketOpts},
    sys::{IpStackCapabilities, get_ip_stack_capabilities, set_tcp_fastopen, socket_bind_dual_stack},
    tcp::{TcpListener, TcpStream},
    udp::UdpSocket,
};

mod option;
mod sys;
pub mod tcp;
pub mod udp;

/// Address family `AF_INET`, `AF_INET6`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddrFamily {
    /// `AF_INET`
    Ipv4,
    /// `AF_INET6`
    Ipv6,
}

impl From<&SocketAddr> for AddrFamily {
    fn from(addr: &SocketAddr) -> Self {
        match *addr {
            SocketAddr::V4(..) => Self::Ipv4,
            SocketAddr::V6(..) => Self::Ipv6,
        }
    }
}

impl From<SocketAddr> for AddrFamily {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(..) => Self::Ipv4,
            SocketAddr::V6(..) => Self::Ipv6,
        }
    }
}

/// Check if `SocketAddr` could be used for creating dual-stack sockets
pub fn is_dual_stack_addr(addr: &SocketAddr) -> bool {
    if let SocketAddr::V6(ref v6) = *addr {
        let ip = v6.ip();
        ip.is_unspecified() || ip.to_ipv4_mapped().is_some()
    } else {
        false
    }
}
