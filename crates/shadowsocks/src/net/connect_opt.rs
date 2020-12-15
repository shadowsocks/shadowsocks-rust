//! Options for connecting to remote server

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ConnectOpts {
    /// Linux mark based routing, going to set by `setsockopt` with `SO_MARK` option
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fwmark: Option<u32>,

    /// An IPC unix socket path for sending file descriptors to call `VpnService.protect`
    ///
    /// This is an [Android shadowsocks implementation](https://github.com/shadowsocks/shadowsocks-android) specific feature
    #[cfg(target_os = "android")]
    pub vpn_protect_path: Option<std::path::PathBuf>,

    /// Outbound socket binds to this IP address, mostly for choosing network interfaces
    ///
    /// It only affects sockets that trying to connect to addresses with the same family
    pub bind_local_addr: Option<IpAddr>,
}

impl Default for ConnectOpts {
    fn default() -> ConnectOpts {
        ConnectOpts {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            fwmark: None,
            #[cfg(target_os = "android")]
            vpn_protect_path: None,
            bind_local_addr: None,
        }
    }
}
