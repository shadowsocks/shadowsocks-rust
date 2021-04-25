use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use cfg_if::cfg_if;
use log::{debug, warn};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;

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

/// Create a `UdpSocket` binded to `addr`
pub async fn create_inbound_udp_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    let set_dual_stack = if let SocketAddr::V6(ref v6) = *addr {
        v6.ip().is_unspecified()
    } else {
        false
    };

    if !set_dual_stack {
        UdpSocket::bind(addr).await
    } else {
        let socket = Socket::new(Domain::for_address(*addr), Type::DGRAM, Some(Protocol::UDP))?;

        if let Err(err) = socket.set_only_v6(false) {
            warn!("failed to set IPV6_V6ONLY: false for listener, error: {}", err);

            // This is not a fatal error, just warn and skip
        }

        let saddr = SockAddr::from(*addr);

        match socket.bind(&saddr) {
            Ok(..) => {}
            Err(ref err) if err.kind() == ErrorKind::AddrInUse => {
                // This is probably 0.0.0.0 with the same port has already been occupied
                debug!(
                    "0.0.0.0:{} may have already been occupied, retry with IPV6_V6ONLY",
                    addr.port()
                );

                if let Err(err) = socket.set_only_v6(true) {
                    warn!("failed to set IPV6_V6ONLY: true for listener, error: {}", err);

                    // This is not a fatal error, just warn and skip
                }
                socket.bind(&saddr)?;
            }
            Err(err) => return Err(err),
        }

        // UdpSocket::from_std requires socket to be non-blocked
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }
}
