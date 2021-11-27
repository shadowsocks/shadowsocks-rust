use std::{
    io,
    net::SocketAddr,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd},
};

use cfg_if::cfg_if;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::net::UdpSocket;

use crate::net::{is_dual_stack_addr, sys::socket_bind_dual_stack, ConnectOpts};

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(any(target_os = "freebsd",
                        target_os = "openbsd",
                        target_os = "netbsd",
                        target_os = "dragonfly",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "watchos",
                        target_os = "tvos"))] {
        mod bsd;
        pub use self::bsd::*;
    } else {
        mod others;
        pub use self::others::*;
    }
}

pub mod uds;

/// Create a `UdpSocket` binded to `addr`
pub async fn create_inbound_udp_socket(addr: &SocketAddr, ipv6_only: bool) -> io::Result<UdpSocket> {
    let set_dual_stack = is_dual_stack_addr(addr);

    if !set_dual_stack {
        UdpSocket::bind(addr).await
    } else {
        let socket = Socket::new(Domain::for_address(*addr), Type::DGRAM, Some(Protocol::UDP))?;
        socket_bind_dual_stack(&socket, addr, ipv6_only)?;

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }
}

pub fn set_common_sockopt_after_connect<S: AsRawFd>(stream: &S, opts: &ConnectOpts) -> io::Result<()> {
    let socket = unsafe { Socket::from_raw_fd(stream.as_raw_fd()) };

    macro_rules! try_sockopt {
        ($socket:ident . $func:ident ($($arg:expr),*)) => {
            match $socket . $func ($($arg),*) {
                Ok(e) => e,
                Err(err) => {
                    let _ = socket.into_raw_fd();
                    return Err(err);
                }
            }
        };
    }

    if opts.tcp.nodelay {
        try_sockopt!(socket.set_nodelay(true));
    }

    if let Some(keepalive_duration) = opts.tcp.keepalive {
        #[allow(unused_mut)]
        let mut keepalive = TcpKeepalive::new().with_time(keepalive_duration);

        #[cfg(any(
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "netbsd",
            target_vendor = "apple",
        ))]
        {
            keepalive = keepalive.with_interval(keepalive_duration);
        }

        try_sockopt!(socket.set_tcp_keepalive(&keepalive));
    }

    let _ = socket.into_raw_fd();

    Ok(())
}
