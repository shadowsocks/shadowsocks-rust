use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use cfg_if::cfg_if;
use log::{debug, warn};
use once_cell::sync::Lazy;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpSocket;

use super::ConnectOpts;

cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub use self::unix::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub use self::windows::*;
    }
}

fn set_common_sockopt_for_connect(addr: SocketAddr, socket: &TcpSocket, opts: &ConnectOpts) -> io::Result<()> {
    // Binds to IP address
    if let Some(baddr) = opts.bind_local_addr {
        match (baddr, addr) {
            (SocketAddr::V4(..), SocketAddr::V4(..)) => {
                socket.bind(baddr)?;
            }
            (SocketAddr::V6(..), SocketAddr::V6(..)) => {
                socket.bind(baddr)?;
            }
            _ => {}
        }
    }

    // Set `SO_SNDBUF`
    if let Some(buf_size) = opts.tcp.send_buffer_size {
        socket.set_send_buffer_size(buf_size)?;
    }

    // Set `SO_RCVBUF`
    if let Some(buf_size) = opts.tcp.recv_buffer_size {
        socket.set_recv_buffer_size(buf_size)?;
    }

    Ok(())
}

#[cfg(all(not(windows), not(unix)))]
#[inline]
fn set_common_sockopt_after_connect_sys(_: &tokio::net::TcpStream, _: &ConnectOpts) -> io::Result<()> {
    Ok(())
}

/// Try to call `bind()` with dual-stack enabled.
///
/// Users have to ensure that `addr` is a dual-stack inbound address (`::`) when `ipv6_only` is `false`.
#[cfg(unix)]
pub fn socket_bind_dual_stack<S>(socket: &S, addr: &SocketAddr, ipv6_only: bool) -> io::Result<()>
where
    S: std::os::unix::io::AsRawFd,
{
    use std::os::unix::prelude::{FromRawFd, IntoRawFd};

    let fd = socket.as_raw_fd();

    let sock = unsafe { Socket::from_raw_fd(fd) };
    let result = socket_bind_dual_stack_inner(&sock, addr, ipv6_only);
    let _ = sock.into_raw_fd();

    result
}

/// Try to call `bind()` with dual-stack enabled.
///
/// Users have to ensure that `addr` is a dual-stack inbound address (`::`) when `ipv6_only` is `false`.
#[cfg(windows)]
pub fn socket_bind_dual_stack<S>(socket: &S, addr: &SocketAddr, ipv6_only: bool) -> io::Result<()>
where
    S: std::os::windows::io::AsRawSocket,
{
    use std::os::windows::prelude::{FromRawSocket, IntoRawSocket};

    let handle = socket.as_raw_socket();

    let sock = unsafe { Socket::from_raw_socket(handle) };
    let result = socket_bind_dual_stack_inner(&sock, addr, ipv6_only);
    let _ = sock.into_raw_socket();

    result
}

fn socket_bind_dual_stack_inner(socket: &Socket, addr: &SocketAddr, ipv6_only: bool) -> io::Result<()> {
    let saddr = SockAddr::from(*addr);

    if ipv6_only {
        // Requested to set IPV6_V6ONLY
        socket.set_only_v6(true)?;
        socket.bind(&saddr)?;
    } else {
        if let Err(err) = socket.set_only_v6(false) {
            warn!("failed to set IPV6_V6ONLY: false for socket, error: {}", err);

            // This is not a fatal error, just warn and skip
        }

        match socket.bind(&saddr) {
            Ok(..) => {}
            Err(ref err) if err.kind() == ErrorKind::AddrInUse => {
                // This is probably 0.0.0.0 with the same port has already been occupied
                debug!(
                    "0.0.0.0:{} may have already been occupied, retry with IPV6_V6ONLY",
                    addr.port()
                );

                if let Err(err) = socket.set_only_v6(true) {
                    warn!("failed to set IPV6_V6ONLY: true for socket, error: {}", err);

                    // This is not a fatal error, just warn and skip
                }
                socket.bind(&saddr)?;
            }
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

/// IP Stack Capabilities
#[derive(Debug, Clone, Copy, Default)]
pub struct IpStackCapabilities {
    /// IP stack supports IPv4
    pub support_ipv4: bool,
    /// IP stack supports IPv6
    pub support_ipv6: bool,
    /// IP stack supports IPv4-mapped-IPv6
    pub support_ipv4_mapped_ipv6: bool,
}

static IP_STACK_CAPABILITIES: Lazy<IpStackCapabilities> = Lazy::new(|| {
    // Reference Implementation: https://github.com/golang/go/blob/master/src/net/ipsock_posix.go

    let mut caps = IpStackCapabilities {
        support_ipv4: false,
        support_ipv6: false,
        support_ipv4_mapped_ipv6: false,
    };

    // Check IPv4
    if Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).is_ok() {
        caps.support_ipv4 = true;
        debug!("IpStackCapability support_ipv4=true");
    }

    // Check IPv6 (::1)
    if let Ok(ipv6_socket) = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) {
        if ipv6_socket.set_only_v6(true).is_ok() {
            let local_host = SockAddr::from(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0));
            if ipv6_socket.bind(&local_host).is_ok() {
                caps.support_ipv6 = true;
                debug!("IpStackCapability support_ipv6=true");
            }
        }
    }

    // Check IPv4-mapped-IPv6 (127.0.0.1)
    if check_ipv4_mapped_ipv6_capability().is_ok() {
        caps.support_ipv4_mapped_ipv6 = true;
        debug!("IpStackCapability support_ipv4_mapped_ipv6=true");
    }

    caps
});

fn check_ipv4_mapped_ipv6_capability() -> io::Result<()> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;

    let local_host = SockAddr::from(SocketAddr::new(Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(), 0));
    socket.bind(&local_host)?;

    Ok(())
}

/// Get globally probed `IpStackCapabilities`
pub fn get_ip_stack_capabilities() -> &'static IpStackCapabilities {
    &IP_STACK_CAPABILITIES
}
