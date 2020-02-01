use std::{io, net::SocketAddr};

use cfg_if::cfg_if;
use tokio::net::UdpSocket;

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(target_os = "macos")] {
        mod macos;
        pub use self::macos::*;
    } else if #[cfg(target_os = "freebsd")] {
        mod freebsd;
        pub use self::freebsd::*;
    } else {
        mod not_supported;
        pub use self::not_supported::*;
    }
}

/// Create a `UdpSocket` binded to `addr`
#[inline(always)]
pub async fn create_socket(addr: &SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}
