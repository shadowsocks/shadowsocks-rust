//! Options for connecting to remote server

use std::{net::SocketAddr, time::Duration};

/// Options for connecting to TCP remote server
#[derive(Debug, Clone, Default)]
pub struct TcpSocketOpts {
    /// TCP socket's `SO_SNDBUF`
    pub send_buffer_size: Option<u32>,

    /// TCP socket's `SO_RCVBUF`
    pub recv_buffer_size: Option<u32>,

    /// `TCP_NODELAY`
    pub nodelay: bool,

    /// `TCP_FASTOPEN`, enables TFO
    pub fastopen: bool,

    /// `SO_KEEPALIVE` and sets `TCP_KEEPIDLE`, `TCP_KEEPINTVL` and `TCP_KEEPCNT` respectively,
    /// enables keep-alive messages on connection-oriented sockets
    pub keepalive: Option<Duration>,

    /// Enable Multipath-TCP (mptcp)
    /// https://en.wikipedia.org/wiki/Multipath_TCP
    ///
    /// Currently only supported on
    /// - macOS (iOS, watchOS, ...) with Client Support only.
    /// - Linux (>5.19)
    pub mptcp: bool,
}

/// Options for UDP server
#[derive(Debug, Clone, Default)]
pub struct UdpSocketOpts {
    /// Maximum Transmission Unit (MTU) for UDP socket `recv`
    ///
    /// NOTE: MTU includes IP header, UDP header, UDP payload
    pub mtu: Option<usize>,

    /// Outbound UDP socket allows IP fragmentation
    pub allow_fragmentation: bool,
}

/// Options for connecting to remote server
#[derive(Debug, Clone, Default)]
pub struct ConnectOpts {
    /// Linux mark based routing, going to set by `setsockopt` with `SO_MARK` option
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fwmark: Option<u32>,

    /// FreeBSD SO_USER_COOKIE
    /// https://www.freebsd.org/cgi/man.cgi?query=setsockopt&sektion=2
    #[cfg(target_os = "freebsd")]
    pub user_cookie: Option<u32>,

    /// An IPC unix socket path for sending file descriptors to call `VpnService.protect`
    ///
    /// This is an [Android shadowsocks implementation](https://github.com/shadowsocks/shadowsocks-android) specific feature
    #[cfg(target_os = "android")]
    pub vpn_protect_path: Option<std::path::PathBuf>,
    #[cfg(target_os = "android")]
    pub vpn_socket_protect: Option<std::sync::Arc<Box<dyn android::SocketProtect + Send + Sync>>>,

    /// Outbound socket binds to this IP address, mostly for choosing network interfaces
    ///
    /// It only affects sockets that trying to connect to addresses with the same family
    pub bind_local_addr: Option<SocketAddr>,

    /// Outbound socket binds to interface
    pub bind_interface: Option<String>,

    /// TCP options
    pub tcp: TcpSocketOpts,

    /// UDP options
    pub udp: UdpSocketOpts,
}

/// Inbound connection options
#[derive(Clone, Debug, Default)]
pub struct AcceptOpts {
    /// TCP options
    pub tcp: TcpSocketOpts,

    /// UDP options
    pub udp: UdpSocketOpts,

    /// Enable IPV6_V6ONLY option for socket
    pub ipv6_only: bool,
}

#[cfg(target_os = "android")]
impl ConnectOpts {
    pub fn set_vpn_socket_protect<F>(&mut self, f: F)
    where
        F: Fn(std::os::unix::io::RawFd) -> std::io::Result<()> + Send + Sync + 'static,
    {
        let protect_fn = Box::new(android::SocketProtectFn { f }) as Box<dyn android::SocketProtect + Send + Sync>;
        self.vpn_socket_protect = Some(std::sync::Arc::new(protect_fn))
    }
}

#[cfg(target_os = "android")]
pub mod android {
    use std::io;
    use std::os::unix::io::RawFd;
    use std::sync::Arc;

    pub trait SocketProtect {
        fn protect(&self, fd: RawFd) -> io::Result<()>;
    }

    pub struct SocketProtectFn<F> {
        pub f: F,
    }

    impl<F> SocketProtect for SocketProtectFn<F>
    where
        F: Fn(RawFd) -> io::Result<()>,
    {
        fn protect(&self, fd: RawFd) -> io::Result<()> {
            (self.f)(fd)
        }
    }

    impl<F> Clone for SocketProtectFn<Arc<F>> {
        fn clone(&self) -> Self {
            Self { f: self.f.clone() }
        }
    }

    impl std::fmt::Debug for dyn SocketProtect + Send + Sync {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("dyn SocketProtect + Send + Sync").finish()
        }
    }
}
