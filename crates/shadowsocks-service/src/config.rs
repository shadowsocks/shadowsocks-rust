//! This is a mod for storing and parsing configuration
//!
//! According to shadowsocks' official documentation, the standard configuration
//! file should be in JSON format:
//!
//! ```ignore
//! {
//!     "server": "127.0.0.1",
//!     "server_port": 1080,
//!     "local_port": 8388,
//!     "password": "the-password",
//!     "timeout": 300,
//!     "method": "aes-256-cfb",
//!     "local_address": "127.0.0.1"
//! }
//! ```
//!
//! But this configuration is not for using multiple shadowsocks server, so we
//! introduce an extended configuration file format:
//!
//! ```ignore
//! {
//!     "servers": [
//!         {
//!             "server": "127.0.0.1",
//!             "server_port": 1080,
//!             "password": "hellofuck",
//!             "method": "bf-cfb"
//!         },
//!         {
//!             "server": "127.0.0.1",
//!             "server_port": 1081,
//!             "password": "hellofuck",
//!             "method": "aes-128-cfb"
//!         }
//!     ],
//!     "local_port": 8388,
//!     "local_address": "127.0.0.1"
//! }
//! ```
//!
//! These defined server will be used with a load balancing algorithm.

use std::{
    borrow::Cow,
    convert::{From, Infallible},
    default::Default,
    env,
    fmt::{self, Debug, Display, Formatter},
    fs::OpenOptions,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    option::Option,
    path::{Path, PathBuf},
    str::FromStr,
    string::ToString,
    time::Duration,
};

use cfg_if::cfg_if;
#[cfg(feature = "local-tun")]
use ipnet::IpNet;
use log::warn;
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "local-tunnel", feature = "local-dns"))]
use shadowsocks::relay::socks5::Address;
use shadowsocks::{
    config::{
        ManagerAddr,
        Mode,
        ReplayAttackPolicy,
        ServerAddr,
        ServerConfig,
        ServerUser,
        ServerUserManager,
        ServerWeight,
    },
    crypto::CipherKind,
    plugin::PluginConfig,
};
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig};

use crate::acl::AccessControl;
#[cfg(feature = "local-dns")]
use crate::local::dns::NameServerAddr;
#[cfg(feature = "local")]
use crate::local::socks::config::Socks5AuthConfig;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum SSDnsConfig {
    Simple(String),
    #[cfg(feature = "trust-dns")]
    TrustDns(ResolverConfig),
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SSSecurityConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_attack: Option<SSSecurityReplayAttackConfig>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SSSecurityReplayAttackConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SSBalancerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_server_rtt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_best_interval: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SSConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    local_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    manager_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manager_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_opts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_args: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    udp_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_max_associations: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none", alias = "shadowsocks")]
    servers: Option<Vec<SSServerExtConfig>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    locals: Option<Vec<SSLocalExtConfig>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<SSDnsConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    no_delay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keep_alive: Option<u64>,

    #[cfg(all(unix, not(target_os = "android")))]
    #[serde(skip_serializing_if = "Option::is_none")]
    nofile: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6_first: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6_only: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fast_open: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    outbound_fwmark: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(target_os = "freebsd")]
    outbound_user_cookie: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    outbound_bind_addr: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    outbound_bind_interface: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    security: Option<SSSecurityConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    balancer: Option<SSBalancerConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    acl: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct SSLocalExtConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    local_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    local_udp_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_udp_port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,

    /// TCP Transparent Proxy type
    #[cfg(feature = "local-redir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_redir: Option<String>,
    /// UDP Transparent Proxy type
    #[cfg(feature = "local-redir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_redir: Option<String>,

    /// Local DNS's address
    ///
    /// Sending DNS query directly to this address
    #[cfg(feature = "local-dns")]
    #[serde(skip_serializing_if = "Option::is_none")]
    local_dns_address: Option<String>,
    #[cfg(feature = "local-dns")]
    #[serde(skip_serializing_if = "Option::is_none")]
    local_dns_port: Option<u16>,
    /// Remote DNS's address
    ///
    /// Sending DNS query through proxy to this address
    #[cfg(feature = "local-dns")]
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_dns_address: Option<String>,
    #[cfg(feature = "local-dns")]
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_dns_port: Option<u16>,

    /// Tunnel
    #[cfg(feature = "local-tunnel")]
    #[serde(skip_serializing_if = "Option::is_none")]
    forward_address: Option<String>,
    #[cfg(feature = "local-tunnel")]
    #[serde(skip_serializing_if = "Option::is_none")]
    forward_port: Option<u16>,

    /// Tun
    #[cfg(feature = "local-tun")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tun_interface_name: Option<String>,
    #[cfg(feature = "local-tun")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tun_interface_address: Option<String>,
    #[cfg(feature = "local-tun")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tun_interface_destination: Option<String>,
    #[cfg(all(feature = "local-tun", unix))]
    #[serde(skip_serializing_if = "Option::is_none")]
    tun_device_fd_from_path: Option<String>,

    /// SOCKS5
    #[cfg(feature = "local")]
    #[serde(skip_serializing_if = "Option::is_none")]
    socks5_auth_config_path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    acl: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SSServerUserConfig {
    name: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SSServerExtConfig {
    // SIP008 https://github.com/shadowsocks/shadowsocks-org/issues/89
    //
    // `address` and `port` are non-standard field name only for shadowsocks-rust
    #[serde(alias = "address")]
    server: String,
    #[serde(alias = "port")]
    server_port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    method: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    users: Option<Vec<SSServerUserConfig>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_opts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_args: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none", alias = "name")]
    remarks: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_weight: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_weight: Option<f32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    acl: Option<String>,
}

/// Server config type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigType {
    /// Config for local
    Local,

    /// Config for server
    Server,

    /// Config for Manager server
    Manager,
}

impl ConfigType {
    /// Check if it is local server type
    pub fn is_local(self) -> bool {
        self == ConfigType::Local
    }

    /// Check if it is remote server type
    pub fn is_server(self) -> bool {
        self == ConfigType::Server
    }

    /// Check if it is manager server type
    pub fn is_manager(self) -> bool {
        self == ConfigType::Manager
    }
}

cfg_if! {
    if #[cfg(feature = "local-redir")] {
        /// Transparent Proxy type
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum RedirType {
            /// For not supported platforms
            NotSupported,

            /// For Linux-like systems' Netfilter `REDIRECT`. Only for TCP connections.
            ///
            /// This is supported from Linux 2.4 Kernel. Document: <https://www.netfilter.org/documentation/index.html#documentation-howto>
            ///
            /// NOTE: Filter rule `REDIRECT` can only be applied to TCP connections.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Redirect,

            /// For Linux-like systems' Netfilter TPROXY rule.
            ///
            /// NOTE: Filter rule `TPROXY` can be applied to TCP and UDP connections.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            TProxy,

            /// Packet Filter (pf)
            ///
            /// Supported by OpenBSD 3.0+, FreeBSD 5.3+, NetBSD 3.0+, Solaris 11.3+, macOS 10.7+, iOS, QNX
            ///
            /// Document: <https://www.freebsd.org/doc/handbook/firewalls-pf.html>
            #[cfg(any(
                target_os = "openbsd",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "solaris",
                target_os = "macos",
                target_os = "ios"
            ))]
            PacketFilter,

            /// IPFW
            ///
            /// Supported by FreeBSD, macOS 10.6- (Have been removed completely on macOS 10.10)
            ///
            /// Document: https://www.freebsd.org/doc/handbook/firewalls-ipfw.html
            #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
            IpFirewall,
        }

        impl RedirType {
            cfg_if! {
                if #[cfg(any(target_os = "linux", target_os = "android"))] {
                    /// Default TCP transparent proxy solution on this platform
                    pub const fn tcp_default() -> RedirType {
                        RedirType::Redirect
                    }

                    /// Available TCP transparent proxy types
                    #[doc(hidden)]
                    pub fn tcp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[RedirType::Redirect.name(), RedirType::TProxy.name()];
                        AVAILABLE_TYPES
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub const fn udp_default() -> RedirType {
                        RedirType::TProxy
                    }

                    /// Available UDP transparent proxy types
                    #[doc(hidden)]
                    pub fn udp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[RedirType::TProxy.name()];
                        AVAILABLE_TYPES
                    }
                } else if #[cfg(any(target_os = "openbsd", target_os = "freebsd"))] {
                    /// Default TCP transparent proxy solution on this platform
                    pub fn tcp_default() -> RedirType {
                        RedirType::PacketFilter
                    }

                    /// Available TCP transparent proxy types
                    #[doc(hidden)]
                    pub fn tcp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[RedirType::PacketFilter.name(), RedirType::IpFirewall.name()];
                        AVAILABLE_TYPES
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub fn udp_default() -> RedirType {
                        RedirType::PacketFilter
                    }

                    /// Available UDP transparent proxy types
                    #[doc(hidden)]
                    pub const fn udp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[RedirType::PacketFilter.name(), RedirType::IpFirewall.name()];
                        AVAILABLE_TYPES
                    }
                } else if #[cfg(any(target_os = "netbsd", target_os = "solaris", target_os = "macos", target_os = "ios"))] {
                    /// Default TCP transparent proxy solution on this platform
                    pub fn tcp_default() -> RedirType {
                        RedirType::PacketFilter
                    }

                    /// Available TCP transparent proxy types
                    #[doc(hidden)]
                    pub const fn tcp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[RedirType::PacketFilter.name(), RedirType::IpFirewall.name()];
                        AVAILABLE_TYPES
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub fn udp_default() -> RedirType {
                        RedirType::NotSupported
                    }

                    /// Available UDP transparent proxy types
                    #[doc(hidden)]
                    pub const fn udp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[];
                        AVAILABLE_TYPES
                    }
                } else {
                    /// Default TCP transparent proxy solution on this platform
                    pub fn tcp_default() -> RedirType {
                        RedirType::NotSupported
                    }

                    /// Available TCP transparent proxy types
                    #[doc(hidden)]
                    pub const fn tcp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[];
                        AVAILABLE_TYPES
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub fn udp_default() -> RedirType {
                        RedirType::NotSupported
                    }

                    /// Available UDP transparent proxy types
                    #[doc(hidden)]
                    pub const fn udp_available_types() -> &'static [&'static str] {
                        const AVAILABLE_TYPES: &[&str] = &[];
                        AVAILABLE_TYPES
                    }
                }
            }

            /// Check if transparent proxy is supported on this platform
            pub fn is_supported(self) -> bool {
                self != RedirType::NotSupported
            }

            /// Name of redirect type (transparent proxy type)
            pub const fn name(self) -> &'static str {
                match self {
                    // Dummy, shouldn't be used in any useful situations
                    RedirType::NotSupported => "not_supported",

                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    RedirType::Redirect => "redirect",

                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    RedirType::TProxy => "tproxy",

                    #[cfg(any(
                        target_os = "openbsd",
                        target_os = "freebsd",
                        target_os = "netbsd",
                        target_os = "solaris",
                        target_os = "macos",
                        target_os = "ios"
                    ))]
                    RedirType::PacketFilter => "pf",

                    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
                    RedirType::IpFirewall => "ipfw",
                }
            }
        }

        impl Display for RedirType {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                f.write_str(self.name())
            }
        }

        /// Error type for `RedirType`'s `FromStr::Err`
        #[derive(Debug)]
        pub struct InvalidRedirType;

        impl Display for InvalidRedirType {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("invalid RedirType")
            }
        }

        impl FromStr for RedirType {
            type Err = InvalidRedirType;

            fn from_str(s: &str) -> Result<RedirType, InvalidRedirType> {
                match s {
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    "redirect" => Ok(RedirType::Redirect),

                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    "tproxy" => Ok(RedirType::TProxy),

                    #[cfg(any(
                        target_os = "openbsd",
                        target_os = "freebsd",
                        target_os = "netbsd",
                        target_os = "solaris",
                        target_os = "macos",
                        target_os = "ios",
                    ))]
                    "pf" => Ok(RedirType::PacketFilter),

                    #[cfg(any(
                        target_os = "freebsd",
                        target_os = "macos",
                        target_os = "ios",
                        target_os = "dragonfly"
                    ))]
                    "ipfw" => Ok(RedirType::IpFirewall),

                    _ => Err(InvalidRedirType),
                }
            }
        }
    }
}

/// Host for servers to bind
///
/// Servers will bind to a port of this host
#[derive(Clone, Debug)]
pub enum ManagerServerHost {
    /// Domain name
    Domain(String),
    /// IP address
    Ip(IpAddr),
}

impl Default for ManagerServerHost {
    fn default() -> ManagerServerHost {
        ManagerServerHost::Ip(Ipv4Addr::UNSPECIFIED.into())
    }
}

impl FromStr for ManagerServerHost {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<IpAddr>() {
            Ok(s) => Ok(ManagerServerHost::Ip(s)),
            Err(..) => Ok(ManagerServerHost::Domain(s.to_owned())),
        }
    }
}

/// Mode of Manager's server
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ManagerServerMode {
    /// Run shadowsocks server in the same process of manager
    Builtin,

    /// Run shadowsocks server in standalone (process) mode
    #[cfg(unix)]
    Standalone,
}

impl Default for ManagerServerMode {
    fn default() -> ManagerServerMode {
        ManagerServerMode::Builtin
    }
}

/// Parsing ManagerServerMode error
#[derive(Debug, Clone, Copy)]
pub struct ManagerServerModeError;

impl Display for ManagerServerModeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ManagerServerMode")
    }
}

impl FromStr for ManagerServerMode {
    type Err = ManagerServerModeError;

    fn from_str(s: &str) -> Result<ManagerServerMode, Self::Err> {
        match s {
            "builtin" => Ok(ManagerServerMode::Builtin),
            #[cfg(unix)]
            "standalone" => Ok(ManagerServerMode::Standalone),
            _ => Err(ManagerServerModeError),
        }
    }
}

impl Display for ManagerServerMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ManagerServerMode::Builtin => f.write_str("builtin"),
            #[cfg(unix)]
            ManagerServerMode::Standalone => f.write_str("standalone"),
        }
    }
}

/// Configuration for Manager
#[derive(Clone, Debug)]
pub struct ManagerConfig {
    /// Address of `ss-manager`. Send servers' statistic data to the manager server
    pub addr: ManagerAddr,
    /// Manager's default method
    pub method: Option<CipherKind>,
    /// Manager's default plugin
    pub plugin: Option<PluginConfig>,
    /// Timeout for TCP connections, setting to manager's created servers
    pub timeout: Option<Duration>,
    /// IP/Host for servers to bind (inbound)
    ///
    /// Note: Outbound address is defined in Config.local_addr
    pub server_host: ManagerServerHost,
    /// Server's mode
    pub mode: Mode,
    /// Server's running mode
    pub server_mode: ManagerServerMode,
    /// Server's command if running in Standalone mode
    #[cfg(unix)]
    pub server_program: String,
    /// Server's working directory if running in Standalone mode
    #[cfg(unix)]
    pub server_working_directory: PathBuf,
}

impl ManagerConfig {
    /// Create a ManagerConfig with default options
    pub fn new(addr: ManagerAddr) -> ManagerConfig {
        ManagerConfig {
            addr,
            method: None,
            plugin: None,
            timeout: None,
            server_host: ManagerServerHost::default(),
            mode: Mode::TcpOnly,
            server_mode: ManagerServerMode::Builtin,
            #[cfg(unix)]
            server_program: "ssserver".to_owned(),
            #[cfg(unix)]
            server_working_directory: match std::env::current_dir() {
                Ok(d) => d,
                Err(..) => "/tmp/shadowsocks-manager".into(),
            },
        }
    }
}

/// Protocol of local server
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProtocolType {
    Socks,
    #[cfg(feature = "local-http")]
    Http,
    #[cfg(feature = "local-tunnel")]
    Tunnel,
    #[cfg(feature = "local-redir")]
    Redir,
    #[cfg(feature = "local-dns")]
    Dns,
    #[cfg(feature = "local-tun")]
    Tun,
}

impl Default for ProtocolType {
    fn default() -> ProtocolType {
        ProtocolType::Socks
    }
}

impl ProtocolType {
    /// As string representation
    pub fn as_str(&self) -> &'static str {
        match *self {
            ProtocolType::Socks => "socks",
            #[cfg(feature = "local-http")]
            ProtocolType::Http => "http",
            #[cfg(feature = "local-tunnel")]
            ProtocolType::Tunnel => "tunnel",
            #[cfg(feature = "local-redir")]
            ProtocolType::Redir => "redir",
            #[cfg(feature = "local-dns")]
            ProtocolType::Dns => "dns",
            #[cfg(feature = "local-tun")]
            ProtocolType::Tun => "tun",
        }
    }

    /// Get all available protocols
    pub fn available_protocols() -> &'static [&'static str] {
        &[
            "socks",
            #[cfg(feature = "local-http")]
            "http",
            #[cfg(feature = "local-tunnel")]
            "tunnel",
            #[cfg(feature = "local-redir")]
            "redir",
            #[cfg(feature = "local-dns")]
            "dns",
            #[cfg(feature = "local-tun")]
            "tun",
        ]
    }
}

/// Error while parsing `ProtocolType` from string
#[derive(Debug)]
pub struct ProtocolTypeError;

impl Display for ProtocolTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ProtocolType")
    }
}

impl FromStr for ProtocolType {
    type Err = ProtocolTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "socks" => Ok(ProtocolType::Socks),
            #[cfg(feature = "local-http")]
            "http" => Ok(ProtocolType::Http),
            #[cfg(feature = "local-tunnel")]
            "tunnel" => Ok(ProtocolType::Tunnel),
            #[cfg(feature = "local-redir")]
            "redir" => Ok(ProtocolType::Redir),
            #[cfg(feature = "local-dns")]
            "dns" => Ok(ProtocolType::Dns),
            #[cfg(feature = "local-tun")]
            "tun" => Ok(ProtocolType::Tun),
            _ => Err(ProtocolTypeError),
        }
    }
}

/// Local server configuration
#[derive(Clone, Debug)]
pub struct LocalConfig {
    /// Listen address for local servers
    pub addr: Option<ServerAddr>,

    pub protocol: ProtocolType,

    /// Mode
    /// Uses global `mode` if not specified
    pub mode: Mode,

    /// UDP server bind address. Uses `addr` if not specified
    ///
    /// Resolving Android's issue: [shadowsocks/shadowsocks-android#2571](https://github.com/shadowsocks/shadowsocks-android/issues/2571)
    pub udp_addr: Option<ServerAddr>,

    /// Destination address for tunnel
    #[cfg(feature = "local-tunnel")]
    pub forward_addr: Option<Address>,

    /// TCP Transparent Proxy type
    #[cfg(feature = "local-redir")]
    pub tcp_redir: RedirType,
    /// UDP Transparent Proxy type
    #[cfg(feature = "local-redir")]
    pub udp_redir: RedirType,

    /// Local DNS's address
    ///
    /// Sending DNS query directly to this address
    #[cfg(feature = "local-dns")]
    pub local_dns_addr: Option<NameServerAddr>,
    /// Remote DNS's address
    ///
    /// Sending DNS query through proxy to this address
    #[cfg(feature = "local-dns")]
    pub remote_dns_addr: Option<Address>,

    /// Tun interface's name
    ///
    /// Linux: eth0, eth1, ...
    /// macOS: utun0, utun1, ...
    #[cfg(feature = "local-tun")]
    pub tun_interface_name: Option<String>,
    /// Tun interface's address and netmask
    #[cfg(feature = "local-tun")]
    pub tun_interface_address: Option<IpNet>,
    /// Tun interface's destination address and netmask
    #[cfg(feature = "local-tun")]
    pub tun_interface_destination: Option<IpNet>,
    /// Tun interface's file descriptor
    #[cfg(all(feature = "local-tun", unix))]
    pub tun_device_fd: Option<std::os::unix::io::RawFd>,
    /// Tun interface's file descriptor read from this Unix Domain Socket
    #[cfg(all(feature = "local-tun", unix))]
    pub tun_device_fd_from_path: Option<PathBuf>,

    /// Set `IPV6_V6ONLY` for listener socket
    pub ipv6_only: bool,

    /// SOCKS5 Authentication configuration
    #[cfg(feature = "local")]
    pub socks5_auth: Socks5AuthConfig,
}

impl LocalConfig {
    /// Create a new `LocalConfig`
    pub fn new(protocol: ProtocolType) -> LocalConfig {
        LocalConfig {
            addr: None,

            protocol,

            mode: Mode::TcpOnly,
            udp_addr: None,

            #[cfg(feature = "local-tunnel")]
            forward_addr: None,

            #[cfg(feature = "local-redir")]
            tcp_redir: RedirType::tcp_default(),
            #[cfg(feature = "local-redir")]
            udp_redir: RedirType::udp_default(),

            #[cfg(feature = "local-dns")]
            local_dns_addr: None,
            #[cfg(feature = "local-dns")]
            remote_dns_addr: None,

            #[cfg(feature = "local-tun")]
            tun_interface_name: None,
            #[cfg(feature = "local-tun")]
            tun_interface_address: None,
            #[cfg(feature = "local-tun")]
            tun_interface_destination: None,
            #[cfg(all(feature = "local-tun", unix))]
            tun_device_fd: None,
            #[cfg(all(feature = "local-tun", unix))]
            tun_device_fd_from_path: None,

            ipv6_only: false,

            #[cfg(feature = "local")]
            socks5_auth: Socks5AuthConfig::default(),
        }
    }

    /// Create a new `LocalConfig` with listen address
    pub fn new_with_addr(addr: ServerAddr, protocol: ProtocolType) -> LocalConfig {
        let mut config = LocalConfig::new(protocol);
        config.addr = Some(addr);
        config
    }

    fn check_integrity(&self) -> Result<(), Error> {
        match self.protocol {
            #[cfg(feature = "local-tun")]
            ProtocolType::Tun => {}

            _ => {
                if self.addr.is_none() {
                    let err = Error::new(ErrorKind::MissingField, "missing `addr` in configuration", None);
                    return Err(err);
                }
            }
        }

        match self.protocol {
            #[cfg(feature = "local-dns")]
            ProtocolType::Dns => {
                if self.local_dns_addr.is_none() || self.remote_dns_addr.is_none() {
                    let err = Error::new(
                        ErrorKind::MissingField,
                        "missing `local_dns_addr` or `remote_dns_addr` in configuration",
                        None,
                    );
                    return Err(err);
                }
            }
            #[cfg(feature = "local-tunnel")]
            ProtocolType::Tunnel => {
                if self.forward_addr.is_none() {
                    let err = Error::new(ErrorKind::MissingField, "missing `forward_addr` in configuration", None);
                    return Err(err);
                }
            }

            #[cfg(feature = "local-http")]
            ProtocolType::Http => {
                if !self.mode.enable_tcp() {
                    let err = Error::new(ErrorKind::Invalid, "TCP mode have to be enabled for http", None);
                    return Err(err);
                }
            }

            _ => {}
        }

        Ok(())
    }

    // Check if it is a basic format of local
    pub fn is_basic(&self) -> bool {
        if self.protocol != ProtocolType::Socks || self.udp_addr.is_some() {
            return false;
        }

        #[cfg(feature = "local-tunnel")]
        if self.forward_addr.is_some() {
            return false;
        }

        #[cfg(feature = "local-redir")]
        if self.tcp_redir != RedirType::tcp_default() || self.udp_redir != RedirType::udp_default() {
            return false;
        }

        #[cfg(feature = "local-dns")]
        if self.local_dns_addr.is_some() || self.remote_dns_addr.is_some() {
            return false;
        }

        true
    }
}

#[derive(Clone, Debug)]
pub enum DnsConfig {
    System,
    #[cfg(feature = "trust-dns")]
    TrustDns(ResolverConfig),
    #[cfg(feature = "local-dns")]
    LocalDns(NameServerAddr),
}

impl Default for DnsConfig {
    fn default() -> DnsConfig {
        DnsConfig::System
    }
}

/// Security Config
#[derive(Clone, Debug, Default)]
pub struct SecurityConfig {
    pub replay_attack: SecurityReplayAttackConfig,
}

#[derive(Clone, Debug, Default)]
pub struct SecurityReplayAttackConfig {
    pub policy: ReplayAttackPolicy,
}

/// Balancer Config
#[derive(Clone, Debug, Default)]
pub struct BalancerConfig {
    /// MAX rtt of servers, which is the timeout duration of each check requests
    pub max_server_rtt: Option<Duration>,
    /// Interval between each checking
    pub check_interval: Option<Duration>,
    /// Interval for checking the best server
    pub check_best_interval: Option<Duration>,
}

/// Address for local to report flow statistic data
#[cfg(feature = "local-flow-stat")]
#[derive(Debug, Clone)]
pub enum LocalFlowStatAddress {
    /// UNIX Domain Socket address
    #[cfg(unix)]
    UnixStreamPath(PathBuf),
    /// TCP Stream Address
    TcpStreamAddr(SocketAddr),
}

/// Server instance config
#[derive(Debug, Clone)]
pub struct ServerInstanceConfig {
    /// Server's config
    pub config: ServerConfig,
    /// Server's private ACL, set to `None` will use the global `AccessControl`
    pub acl: Option<AccessControl>,
}

impl ServerInstanceConfig {
    /// Create with `ServerConfig`
    pub fn with_server_config(config: ServerConfig) -> ServerInstanceConfig {
        ServerInstanceConfig { config, acl: None }
    }
}

/// Local instance config
#[derive(Debug, Clone)]
pub struct LocalInstanceConfig {
    /// Local server's config
    pub config: LocalConfig,
    /// Server's private ACL, set to `None` will use the global `AccessControl`
    pub acl: Option<AccessControl>,
}

impl LocalInstanceConfig {
    /// Create with `LocalConfig`
    pub fn with_local_config(config: LocalConfig) -> LocalInstanceConfig {
        LocalInstanceConfig { config, acl: None }
    }
}

/// Configuration
#[derive(Clone, Debug)]
pub struct Config {
    /// Remote ShadowSocks server configurations
    pub server: Vec<ServerInstanceConfig>,
    /// Local server configuration
    pub local: Vec<LocalInstanceConfig>,

    /// DNS configuration, uses system-wide DNS configuration by default
    ///
    /// Value could be a `IpAddr`, uses UDP DNS protocol with port `53`. For example: `8.8.8.8`
    ///
    /// Also Value could be some pre-defined DNS server names:
    ///
    /// - `google`
    /// - `cloudflare`, `cloudflare_tls`, `cloudflare_https`
    /// - `quad9`, `quad9_tls`
    pub dns: DnsConfig,
    /// Uses IPv6 addresses first
    ///
    /// Set to `true` if you want to query IPv6 addresses before IPv4
    pub ipv6_first: bool,
    /// Set `IPV6_V6ONLY` for listener sockets
    pub ipv6_only: bool,

    /// Set `TCP_NODELAY` socket option
    pub no_delay: bool,
    /// Set `TCP_FASTOPEN` socket option
    pub fast_open: bool,
    /// Set TCP Keep-Alive duration, will set both `TCP_KEEPIDLE` and `TCP_KEEPINTVL`
    ///
    /// <https://github.com/shadowsocks/shadowsocks-rust/issues/546>
    ///
    /// If this is not set, sockets will be set with a default timeout
    pub keep_alive: Option<Duration>,

    /// `RLIMIT_NOFILE` option for *nix systems
    #[cfg(all(unix, not(target_os = "android")))]
    pub nofile: Option<u64>,

    /// Set `SO_MARK` socket option for outbound sockets
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub outbound_fwmark: Option<u32>,
    /// Set `SO_USER_COOKIE` socket option for outbound sockets
    #[cfg(target_os = "freebsd")]
    pub outbound_user_cookie: Option<u32>,
    /// Set `SO_BINDTODEVICE` (Linux), `IP_BOUND_IF` (BSD), `IP_UNICAST_IF` (Windows) socket option for outbound sockets
    pub outbound_bind_interface: Option<String>,
    /// Outbound sockets will `bind` to this address
    pub outbound_bind_addr: Option<IpAddr>,
    /// Path to protect callback unix address, only for Android
    #[cfg(target_os = "android")]
    pub outbound_vpn_protect_path: Option<PathBuf>,

    /// Set `SO_SNDBUF` for inbound sockets
    pub inbound_send_buffer_size: Option<u32>,
    /// Set `SO_RCVBUF` for inbound sockets
    pub inbound_recv_buffer_size: Option<u32>,
    /// Set `SO_SNDBUF` for outbound sockets
    pub outbound_send_buffer_size: Option<u32>,
    /// Set `SO_RCVBUF` for outbound sockets
    pub outbound_recv_buffer_size: Option<u32>,

    /// Manager's configuration
    pub manager: Option<ManagerConfig>,

    /// Config is for Client or Server
    pub config_type: ConfigType,

    /// Timeout for UDP Associations, default is 5 minutes
    pub udp_timeout: Option<Duration>,
    /// Maximum number of UDP Associations, default is unconfigured
    pub udp_max_associations: Option<usize>,

    /// ACL configuration (Global)
    ///
    /// Could be overwritten by servers/locals' private `acl`
    pub acl: Option<AccessControl>,

    /// Flow statistic report Unix socket path (only for Android)
    #[cfg(feature = "local-flow-stat")]
    pub local_stat_addr: Option<LocalFlowStatAddress>,

    /// Replay attack policy
    pub security: SecurityConfig,

    /// Balancer config of local server
    pub balancer: BalancerConfig,

    /// Configuration file path, the actual path of the configuration.
    /// This is normally for auto-reloading if implementation supports.
    pub config_path: Option<PathBuf>,

    #[doc(hidden)]
    /// Workers in runtime
    /// It should be replaced with metrics APIs: https://github.com/tokio-rs/tokio/issues/4073
    pub worker_count: usize,
}

/// Configuration parsing error kind
#[derive(Copy, Clone, Debug)]
pub enum ErrorKind {
    /// Missing required fields in JSON configuration
    MissingField,
    /// Missing some keys that must be provided together
    Malformed,
    /// Invalid value of some configuration keys
    Invalid,
    /// Invalid JSON
    JsonParsingError,
    /// `std::io::Error`
    IoError,
}

/// Configuration parsing error
pub struct Error {
    pub kind: ErrorKind,
    pub desc: &'static str,
    pub detail: Option<String>,
}

impl Error {
    pub fn new(kind: ErrorKind, desc: &'static str, detail: Option<String>) -> Error {
        Error { kind, desc, detail }
    }
}

macro_rules! impl_from {
    ($error:ty, $kind:expr, $desc:expr) => {
        impl From<$error> for Error {
            fn from(err: $error) -> Self {
                Error::new($kind, $desc, Some(format!("{:?}", err)))
            }
        }
    };
}

impl_from!(::std::io::Error, ErrorKind::IoError, "error while reading file");
impl_from!(json5::Error, ErrorKind::JsonParsingError, "json parse error");

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.detail {
            None => write!(f, "{}", self.desc),
            Some(ref det) => write!(f, "{} {}", self.desc, det),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.detail {
            None => f.write_str(self.desc),
            Some(ref d) => write!(f, "{}, {}", self.desc, d),
        }
    }
}

impl Config {
    /// Creates an empty configuration
    pub fn new(config_type: ConfigType) -> Config {
        Config {
            server: Vec::new(),
            local: Vec::new(),

            dns: DnsConfig::default(),
            ipv6_first: false,
            ipv6_only: false,

            no_delay: false,
            fast_open: false,
            keep_alive: None,

            #[cfg(all(unix, not(target_os = "android")))]
            nofile: None,

            #[cfg(any(target_os = "linux", target_os = "android"))]
            outbound_fwmark: None,
            #[cfg(target_os = "freebsd")]
            outbound_user_cookie: None,
            outbound_bind_interface: None,
            outbound_bind_addr: None,
            #[cfg(target_os = "android")]
            outbound_vpn_protect_path: None,

            inbound_send_buffer_size: None,
            inbound_recv_buffer_size: None,
            outbound_send_buffer_size: None,
            outbound_recv_buffer_size: None,

            manager: None,

            config_type,

            udp_timeout: None,
            udp_max_associations: None,

            acl: None,

            #[cfg(feature = "local-flow-stat")]
            local_stat_addr: None,

            security: SecurityConfig::default(),

            balancer: BalancerConfig::default(),

            config_path: None,

            worker_count: 1,
        }
    }

    fn load_from_ssconfig(config: SSConfig, config_type: ConfigType) -> Result<Config, Error> {
        let mut nconfig = Config::new(config_type);

        // Client
        //
        // local_address is allowed to be NULL, which means to bind to ::1 or 127.0.0.1
        //
        // https://shadowsocks.org/en/config/quick-guide.html
        #[inline]
        fn get_local_address(local_address: Option<String>, local_port: u16, ipv6_first: bool) -> ServerAddr {
            match local_address {
                Some(addr) => {
                    match addr.parse::<IpAddr>() {
                        Ok(ip) => ServerAddr::from(SocketAddr::new(ip, local_port)),
                        Err(..) => {
                            // treated as domain
                            ServerAddr::from((addr, local_port))
                        }
                    }
                }
                None => {
                    // Implementation note: This is not implemented like libev which will choose IPv6 or IPv6 LoopBack address
                    // by checking all its remote servers if all of them supports IPv6.
                    let ip = if ipv6_first {
                        Ipv6Addr::LOCALHOST.into()
                    } else {
                        Ipv4Addr::LOCALHOST.into()
                    };

                    ServerAddr::from(SocketAddr::new(ip, local_port))
                }
            }
        }

        // Mode
        let mut global_mode = Mode::TcpOnly;
        if let Some(m) = config.mode {
            match m.parse::<Mode>() {
                Ok(xm) => global_mode = xm,
                Err(..) => {
                    let e = Error::new(
                        ErrorKind::Malformed,
                        "malformed `mode`, must be one of `tcp_only`, `udp_only` and `tcp_and_udp`",
                        None,
                    );
                    return Err(e);
                }
            }
        }

        match config_type {
            ConfigType::Local => {
                // Standard config
                if config.local_address.is_some() && config.local_port.unwrap_or(0) == 0 {
                    let err = Error::new(ErrorKind::MissingField, "missing `local_port`", None);
                    return Err(err);
                }

                if let Some(local_port) = config.local_port {
                    // local_port won't be 0, it was checked above
                    assert_ne!(local_port, 0);

                    let local_addr =
                        get_local_address(config.local_address, local_port, config.ipv6_first.unwrap_or(false));

                    // shadowsocks uses SOCKS5 by default
                    let mut local_config = LocalConfig::new(ProtocolType::Socks);
                    local_config.addr = Some(local_addr);
                    local_config.mode = global_mode;
                    local_config.protocol = match config.protocol {
                        None => ProtocolType::Socks,
                        Some(p) => match p.parse::<ProtocolType>() {
                            Ok(p) => p,
                            Err(..) => {
                                let err = Error::new(
                                    ErrorKind::Malformed,
                                    "`protocol` invalid",
                                    Some(format!("unrecognized protocol {p}")),
                                );
                                return Err(err);
                            }
                        },
                    };

                    let local_instance = LocalInstanceConfig {
                        config: local_config,
                        acl: None,
                    };

                    nconfig.local.push(local_instance);
                }

                // Ext locals
                // `locals` are only effective in local server
                if let Some(locals) = config.locals {
                    for local in locals {
                        if local.disabled.unwrap_or(false) {
                            continue;
                        }

                        let protocol = match local.protocol {
                            None => ProtocolType::Socks,
                            Some(p) => match p.parse::<ProtocolType>() {
                                Ok(p) => p,
                                Err(..) => {
                                    let err = Error::new(
                                        ErrorKind::Malformed,
                                        "`protocol` invalid",
                                        Some(format!("unrecognized protocol {p}")),
                                    );
                                    return Err(err);
                                }
                            },
                        };

                        let mut local_config = LocalConfig::new(protocol);

                        if let Some(local_port) = local.local_port {
                            if local_port == 0 {
                                let err = Error::new(ErrorKind::Malformed, "`local_port` cannot be 0", None);
                                return Err(err);
                            }

                            let local_addr =
                                get_local_address(local.local_address, local_port, config.ipv6_first.unwrap_or(false));
                            local_config.addr = Some(local_addr);
                        } else if local.local_address.is_some() {
                            let err = Error::new(ErrorKind::Malformed, "missing `local_port`", None);
                            return Err(err);
                        }

                        if let Some(local_udp_port) = local.local_udp_port {
                            if local_udp_port == 0 {
                                let err = Error::new(ErrorKind::Malformed, "`local_udp_port` cannot be 0", None);
                                return Err(err);
                            }

                            let local_udp_addr = get_local_address(
                                local.local_udp_address,
                                local_udp_port,
                                config.ipv6_first.unwrap_or(false),
                            );

                            local_config.udp_addr = Some(local_udp_addr);
                        }

                        match local.mode {
                            Some(mode) => match mode.parse::<Mode>() {
                                Ok(mode) => local_config.mode = mode,
                                Err(..) => {
                                    let err = Error::new(ErrorKind::Malformed, "invalid `mode`", None);
                                    return Err(err);
                                }
                            },
                            None => {
                                local_config.mode = global_mode;
                            }
                        }

                        #[cfg(feature = "local-tunnel")]
                        if let Some(forward_address) = local.forward_address {
                            let forward_port = match local.forward_port {
                                None | Some(0) => {
                                    let err =
                                        Error::new(ErrorKind::Malformed, "`forward_port` cannot be missing or 0", None);
                                    return Err(err);
                                }
                                Some(p) => p,
                            };

                            local_config.forward_addr = Some(match forward_address.parse::<IpAddr>() {
                                Ok(ip) => Address::from(SocketAddr::new(ip, forward_port)),
                                Err(..) => Address::from((forward_address, forward_port)),
                            });
                        }

                        #[cfg(feature = "local-redir")]
                        if let Some(tcp_redir) = local.tcp_redir {
                            match tcp_redir.parse::<RedirType>() {
                                Ok(r) => local_config.tcp_redir = r,
                                Err(..) => {
                                    let err = Error::new(ErrorKind::Malformed, "`tcp_redir` invalid", None);
                                    return Err(err);
                                }
                            }
                        }

                        #[cfg(feature = "local-redir")]
                        if let Some(udp_redir) = local.udp_redir {
                            match udp_redir.parse::<RedirType>() {
                                Ok(r) => local_config.udp_redir = r,
                                Err(..) => {
                                    let err = Error::new(ErrorKind::Malformed, "`udp_redir` invalid", None);
                                    return Err(err);
                                }
                            }
                        }

                        #[cfg(feature = "local-dns")]
                        if let Some(local_dns_address) = local.local_dns_address {
                            match local_dns_address.parse::<IpAddr>() {
                                Ok(ip) => {
                                    local_config.local_dns_addr = Some(NameServerAddr::SocketAddr(SocketAddr::new(
                                        ip,
                                        local.local_dns_port.unwrap_or(53),
                                    )));
                                }
                                #[cfg(unix)]
                                Err(..) => {
                                    local_config.local_dns_addr =
                                        Some(NameServerAddr::UnixSocketAddr(PathBuf::from(local_dns_address)));
                                }
                                #[cfg(not(unix))]
                                Err(..) => {
                                    let err = Error::new(ErrorKind::Malformed, "`local_dns_address` invalid", None);
                                    return Err(err);
                                }
                            }
                        }

                        #[cfg(feature = "local-dns")]
                        if let Some(remote_dns_address) = local.remote_dns_address {
                            let remote_dns_port = local.remote_dns_port.unwrap_or(53);
                            local_config.remote_dns_addr = Some(match remote_dns_address.parse::<IpAddr>() {
                                Ok(ip) => Address::from(SocketAddr::new(ip, remote_dns_port)),
                                Err(..) => Address::from((remote_dns_address, remote_dns_port)),
                            });
                        }

                        #[cfg(feature = "local-tun")]
                        if let Some(tun_interface_address) = local.tun_interface_address {
                            match tun_interface_address.parse::<IpNet>() {
                                Ok(addr) => local_config.tun_interface_address = Some(addr),
                                Err(..) => {
                                    let err = Error::new(ErrorKind::Malformed, "`tun_interface_address` invalid", None);
                                    return Err(err);
                                }
                            }
                        }

                        #[cfg(feature = "local-tun")]
                        if let Some(tun_interface_name) = local.tun_interface_name {
                            local_config.tun_interface_name = Some(tun_interface_name);
                        }

                        #[cfg(all(feature = "local-tun", unix))]
                        if let Some(tun_device_fd_from_path) = local.tun_device_fd_from_path {
                            local_config.tun_device_fd_from_path = Some(From::from(tun_device_fd_from_path));
                        }

                        #[cfg(feature = "local")]
                        if let Some(socks5_auth_config_path) = local.socks5_auth_config_path {
                            local_config.socks5_auth = Socks5AuthConfig::load_from_file(&socks5_auth_config_path)?;
                        }

                        let mut local_instance = LocalInstanceConfig {
                            config: local_config,
                            acl: None,
                        };

                        if let Some(acl_path) = local.acl {
                            let acl = match AccessControl::load_from_file(&acl_path) {
                                Ok(acl) => acl,
                                Err(err) => {
                                    let err = Error::new(
                                        ErrorKind::Invalid,
                                        "acl loading failed",
                                        Some(format!("file {acl_path}, error: {err}")),
                                    );
                                    return Err(err);
                                }
                            };
                            local_instance.acl = Some(acl);
                        }

                        nconfig.local.push(local_instance);
                    }
                }
            }
            ConfigType::Server | ConfigType::Manager => {
                // NOTE: IGNORED.
                // servers only uses `local_address` for binding outbound interfaces
                //
                // This behavior causes lots of confusion. use outbound_bind_addr instead
            }
        }

        // Standard config
        // Server
        match (config.server, config.server_port, config.password, &config.method) {
            (Some(address), Some(port), pwd_opt, Some(m)) => {
                let addr = match address.parse::<Ipv4Addr>() {
                    Ok(v4) => ServerAddr::SocketAddr(SocketAddr::V4(SocketAddrV4::new(v4, port))),
                    Err(..) => match address.parse::<Ipv6Addr>() {
                        Ok(v6) => ServerAddr::SocketAddr(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0))),
                        Err(..) => ServerAddr::DomainName(address, port),
                    },
                };

                let method = match m.parse::<CipherKind>() {
                    Ok(m) => m,
                    Err(..) => {
                        let err = Error::new(
                            ErrorKind::Invalid,
                            "unsupported method",
                            Some(format!("`{m}` is not a supported method")),
                        );
                        return Err(err);
                    }
                };

                // Only "password" support getting from environment variable.
                let password = match pwd_opt {
                    Some(ref pwd) => read_variable_field_value(pwd),
                    None => {
                        if method.is_none() {
                            String::new().into()
                        } else {
                            let err = Error::new(
                                ErrorKind::MissingField,
                                "`password` is required",
                                Some(format!("`password` is required for method {method}")),
                            );
                            return Err(err);
                        }
                    }
                };

                let mut nsvr = ServerConfig::new(addr, password, method);
                nsvr.set_mode(global_mode);

                if let Some(ref p) = config.plugin {
                    // SIP008 allows "plugin" to be an empty string
                    // Empty string implies "no plugin"
                    if !p.is_empty() {
                        let plugin = PluginConfig {
                            plugin: p.clone(),
                            plugin_opts: config.plugin_opts.clone(),
                            plugin_args: config.plugin_args.clone().unwrap_or_default(),
                        };
                        nsvr.set_plugin(plugin);
                    }
                }

                if let Some(timeout) = config.timeout.map(Duration::from_secs) {
                    nsvr.set_timeout(timeout);
                }

                let server_instance = ServerInstanceConfig {
                    config: nsvr,
                    acl: None,
                };

                nconfig.server.push(server_instance);
            }
            (None, None, None, Some(_)) if config_type.is_manager() => {
                // Set the default method for manager
            }
            (None, None, None, None) => (),
            _ => {
                let err = Error::new(
                    ErrorKind::Malformed,
                    "`server`, `server_port`, `method`, `password` must be provided together",
                    None,
                );
                return Err(err);
            }
        }

        // Ext servers
        if let Some(servers) = config.servers {
            for svr in servers {
                // Skip if server is disabled
                if svr.disabled.unwrap_or(false) {
                    continue;
                }

                let address = svr.server;
                let port = svr.server_port;

                let addr = match address.parse::<Ipv4Addr>() {
                    Ok(v4) => ServerAddr::SocketAddr(SocketAddr::V4(SocketAddrV4::new(v4, port))),
                    Err(..) => match address.parse::<Ipv6Addr>() {
                        Ok(v6) => ServerAddr::SocketAddr(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0))),
                        Err(..) => ServerAddr::DomainName(address, port),
                    },
                };

                let method = match svr.method.parse::<CipherKind>() {
                    Ok(m) => m,
                    Err(..) => {
                        let err = Error::new(
                            ErrorKind::Invalid,
                            "unsupported method",
                            Some(format!("`{}` is not a supported method", svr.method)),
                        );
                        return Err(err);
                    }
                };

                // Only "password" support getting from environment variable.
                let password = match svr.password {
                    Some(ref pwd) => read_variable_field_value(pwd),
                    None => {
                        if method.is_none() {
                            String::new().into()
                        } else {
                            let err = Error::new(
                                ErrorKind::MissingField,
                                "`password` is required",
                                Some(format!("`password` is required for method {method}")),
                            );
                            return Err(err);
                        }
                    }
                };

                let mut nsvr = ServerConfig::new(addr, password, method);

                // Extensible Identity Header, Users
                if let Some(users) = svr.users {
                    let mut user_manager = ServerUserManager::new();

                    for user in users {
                        let user = match ServerUser::with_encoded_key(user.name, &user.password) {
                            Ok(u) => u,
                            Err(..) => {
                                let err = Error::new(
                                    ErrorKind::Malformed,
                                    "`users[].password` should be base64 encoded",
                                    None,
                                );
                                return Err(err);
                            }
                        };

                        user_manager.add_user(user);
                    }

                    nsvr.set_user_manager(user_manager);
                }

                match svr.mode {
                    Some(mode) => match mode.parse::<Mode>() {
                        Ok(mode) => nsvr.set_mode(mode),
                        Err(..) => {
                            let err = Error::new(ErrorKind::Invalid, "invalid `mode`", None);
                            return Err(err);
                        }
                    },
                    None => {
                        // Server will derive mode from the global scope
                        if matches!(config_type, ConfigType::Server | ConfigType::Manager) {
                            nsvr.set_mode(global_mode);
                        }
                    }
                }

                if let Some(p) = svr.plugin {
                    // SIP008 allows "plugin" to be an empty string
                    // Empty string implies "no plugin"
                    if !p.is_empty() {
                        let plugin = PluginConfig {
                            plugin: p,
                            plugin_opts: svr.plugin_opts,
                            plugin_args: svr.plugin_args.unwrap_or_default(),
                        };
                        nsvr.set_plugin(plugin);
                    }
                }

                if let Some(timeout) = config.timeout.map(Duration::from_secs) {
                    nsvr.set_timeout(timeout);
                }

                if let Some(remarks) = svr.remarks {
                    nsvr.set_remarks(remarks);
                }

                if let Some(id) = svr.id {
                    nsvr.set_id(id);
                }

                if svr.tcp_weight.is_some() || svr.udp_weight.is_some() {
                    let tcp_weight = svr.tcp_weight.unwrap_or(1.0);
                    if !(0.0..=1.0).contains(&tcp_weight) {
                        let err = Error::new(ErrorKind::Invalid, "invalid `tcp_weight`, must be in [0, 1]", None);
                        return Err(err);
                    }
                    let udp_weight = svr.udp_weight.unwrap_or(1.0);
                    if !(0.0..=1.0).contains(&udp_weight) {
                        let err = Error::new(ErrorKind::Invalid, "invalid `udp_weight`, must be in [0, 1]", None);
                        return Err(err);
                    }
                    let mut weight = ServerWeight::new();
                    weight.set_tcp_weight(tcp_weight);
                    weight.set_udp_weight(udp_weight);
                    nsvr.set_weight(weight);
                }

                let mut server_instance = ServerInstanceConfig {
                    config: nsvr,
                    acl: None,
                };

                if let Some(acl_path) = svr.acl {
                    let acl = match AccessControl::load_from_file(&acl_path) {
                        Ok(acl) => acl,
                        Err(err) => {
                            let err = Error::new(
                                ErrorKind::Invalid,
                                "acl loading failed",
                                Some(format!("file {acl_path}, error: {err}")),
                            );
                            return Err(err);
                        }
                    };
                    server_instance.acl = Some(acl);
                }

                nconfig.server.push(server_instance);
            }
        }

        // Set timeout globally
        if let Some(timeout) = config.timeout {
            let timeout = Duration::from_secs(timeout);
            // Set as a default timeout
            for inst in &mut nconfig.server {
                let svr = &mut inst.config;
                if svr.timeout().is_none() {
                    svr.set_timeout(timeout);
                }
            }
        }

        // Manager Address
        if let Some(ma) = config.manager_address {
            let manager = match config.manager_port {
                Some(port) => {
                    match ma.parse::<IpAddr>() {
                        Ok(ip) => ManagerAddr::from(SocketAddr::new(ip, port)),
                        Err(..) => {
                            // treated as domain
                            ManagerAddr::from((ma, port))
                        }
                    }
                }
                #[cfg(unix)]
                None => ManagerAddr::from(PathBuf::from(ma)),
                #[cfg(not(unix))]
                None => {
                    let e = Error::new(ErrorKind::MissingField, "missing `manager_port`", None);
                    return Err(e);
                }
            };

            let mut manager_config = ManagerConfig::new(manager);
            manager_config.mode = global_mode;

            if let Some(ref m) = config.method {
                match m.parse::<CipherKind>() {
                    Ok(method) => manager_config.method = Some(method),
                    Err(..) => {
                        let err = Error::new(
                            ErrorKind::Invalid,
                            "unsupported method",
                            Some(format!("`{m}` is not a supported method")),
                        );
                        return Err(err);
                    }
                }
            }

            if let Some(p) = config.plugin {
                // SIP008 allows "plugin" to be an empty string
                // Empty string implies "no plugin"
                if !p.is_empty() {
                    manager_config.plugin = Some(PluginConfig {
                        plugin: p,
                        plugin_opts: config.plugin_opts,
                        plugin_args: config.plugin_args.unwrap_or_default(),
                    });
                }
            }

            nconfig.manager = Some(manager_config);
        }

        // DNS
        {
            match config.dns {
                Some(SSDnsConfig::Simple(ds)) => nconfig.set_dns_formatted(&ds)?,
                #[cfg(feature = "trust-dns")]
                Some(SSDnsConfig::TrustDns(c)) => nconfig.dns = DnsConfig::TrustDns(c),
                None => nconfig.dns = DnsConfig::System,
            }
        }

        // TCP nodelay
        if let Some(b) = config.no_delay {
            nconfig.no_delay = b;
        }

        // TCP fast open
        if let Some(b) = config.fast_open {
            nconfig.fast_open = b;
        }

        // TCP Keep-Alive
        if let Some(d) = config.keep_alive {
            nconfig.keep_alive = Some(Duration::from_secs(d));
        }

        // UDP
        nconfig.udp_timeout = config.udp_timeout.map(Duration::from_secs);

        // Maximum associations to be kept simultaneously
        nconfig.udp_max_associations = config.udp_max_associations;

        // RLIMIT_NOFILE
        #[cfg(all(unix, not(target_os = "android")))]
        {
            nconfig.nofile = config.nofile;
        }

        // Uses IPv6 first
        if let Some(f) = config.ipv6_first {
            nconfig.ipv6_first = f;
        }

        // IPV6_V6ONLY
        if let Some(o) = config.ipv6_only {
            nconfig.ipv6_only = o;
        }

        // SO_MARK
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fwmark) = config.outbound_fwmark {
            nconfig.outbound_fwmark = Some(fwmark);
        }

        // SO_USER_COOKIE
        #[cfg(target_os = "freebsd")]
        if let Some(user_cookie) = config.outbound_user_cookie {
            nconfig.outbound_user_cookie = Some(user_cookie);
        }

        // Outbound bind() address
        if let Some(bind_addr) = config.outbound_bind_addr {
            match bind_addr.parse::<IpAddr>() {
                Ok(b) => nconfig.outbound_bind_addr = Some(b),
                Err(..) => {
                    let err = Error::new(ErrorKind::Invalid, "invalid outbound_bind_addr", None);
                    return Err(err);
                }
            }
        }

        // Bind device / interface
        nconfig.outbound_bind_interface = config.outbound_bind_interface;

        // Security
        if let Some(sec) = config.security {
            if let Some(replay_attack) = sec.replay_attack {
                if let Some(policy) = replay_attack.policy {
                    match policy.parse::<ReplayAttackPolicy>() {
                        Ok(p) => nconfig.security.replay_attack.policy = p,
                        Err(..) => {
                            let err = Error::new(ErrorKind::Invalid, "invalid replay attack policy", None);
                            return Err(err);
                        }
                    }
                }
            }
        }

        if let Some(balancer) = config.balancer {
            nconfig.balancer = BalancerConfig {
                max_server_rtt: balancer.max_server_rtt.map(Duration::from_secs),
                check_interval: balancer.check_interval.map(Duration::from_secs),
                check_best_interval: balancer.check_best_interval.map(Duration::from_secs),
            };
        }

        if let Some(acl_path) = config.acl {
            let acl = match AccessControl::load_from_file(&acl_path) {
                Ok(acl) => acl,
                Err(err) => {
                    let err = Error::new(
                        ErrorKind::Invalid,
                        "acl loading failed",
                        Some(format!("file {acl_path}, error: {err}")),
                    );
                    return Err(err);
                }
            };
            nconfig.acl = Some(acl);
        }

        Ok(nconfig)
    }

    /// Set DNS configuration in string format
    ///
    /// 1. `[(unix|tcp|udp)://]host[:port][,host[:port]]...`
    /// 2. Pre-defined. Like `google`, `cloudflare`
    pub fn set_dns_formatted(&mut self, dns: &str) -> Result<(), Error> {
        self.dns = match dns {
            "system" => DnsConfig::System,

            #[cfg(feature = "trust-dns")]
            "google" => DnsConfig::TrustDns(ResolverConfig::google()),

            #[cfg(feature = "trust-dns")]
            "cloudflare" => DnsConfig::TrustDns(ResolverConfig::cloudflare()),
            #[cfg(all(feature = "trust-dns", feature = "dns-over-tls"))]
            "cloudflare_tls" => DnsConfig::TrustDns(ResolverConfig::cloudflare_tls()),
            #[cfg(all(feature = "trust-dns", feature = "dns-over-https"))]
            "cloudflare_https" => DnsConfig::TrustDns(ResolverConfig::cloudflare_https()),

            #[cfg(feature = "trust-dns")]
            "quad9" => DnsConfig::TrustDns(ResolverConfig::quad9()),
            #[cfg(all(feature = "trust-dns", feature = "dns-over-tls"))]
            "quad9_tls" => DnsConfig::TrustDns(ResolverConfig::quad9_tls()),
            #[cfg(all(feature = "trust-dns", feature = "dns-over-https"))]
            "quad9_https" => DnsConfig::TrustDns(ResolverConfig::quad9_https()),

            nameservers => self.parse_dns_nameservers(nameservers)?,
        };

        Ok(())
    }

    #[cfg(any(feature = "trust-dns", feature = "local-dns"))]
    fn parse_dns_nameservers(&mut self, nameservers: &str) -> Result<DnsConfig, Error> {
        #[cfg(all(unix, feature = "local-dns"))]
        if let Some(nameservers) = nameservers.strip_prefix("unix://") {
            // A special DNS server only for shadowsocks-android
            // It serves like a TCP DNS server but using unix domain sockets

            return Ok(DnsConfig::LocalDns(NameServerAddr::UnixSocketAddr(PathBuf::from(
                nameservers,
            ))));
        }

        enum DnsProtocol {
            Tcp,
            Udp,
            Both,
        }

        impl DnsProtocol {
            fn enable_tcp(&self) -> bool {
                matches!(*self, DnsProtocol::Tcp | DnsProtocol::Both)
            }

            fn enable_udp(&self) -> bool {
                matches!(*self, DnsProtocol::Udp | DnsProtocol::Both)
            }
        }

        let mut protocol = DnsProtocol::Both;

        let mut nameservers = nameservers;
        if nameservers.starts_with("tcp://") {
            protocol = DnsProtocol::Tcp;
            nameservers = &nameservers[6..];
        } else if nameservers.starts_with("udp://") {
            protocol = DnsProtocol::Udp;
            nameservers = &nameservers[6..];
        }

        // If enables Trust-DNS, then it supports multiple nameservers
        //
        // Set ips directly
        // Similar to shadowsocks-libev's `ares_set_servers_ports_csv`
        //
        // ```
        // host[:port][,host[:port]]...
        // ```
        //
        // For example:
        //     `192.168.1.100,192.168.1.101,3.4.5.6`
        let mut c = ResolverConfig::new();
        for part in nameservers.split(',') {
            let socket_addr = if let Ok(socket_addr) = part.parse::<SocketAddr>() {
                socket_addr
            } else if let Ok(ipaddr) = part.parse::<IpAddr>() {
                SocketAddr::new(ipaddr, 53)
            } else {
                let e = Error::new(
                    ErrorKind::Invalid,
                    "invalid `dns` value, can only be [(tcp|udp)://]host[:port][,host[:port]]..., or unix:///path/to/dns, or predefined keys like \"google\", \"cloudflare\"",
                    None,
                );
                return Err(e);
            };

            if protocol.enable_udp() {
                c.add_name_server(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_nx_responses: false,
                    #[cfg(any(feature = "dns-over-tls", feature = "dns-over-https"))]
                    tls_config: None,
                    bind_addr: None,
                });
            }
            if protocol.enable_tcp() {
                c.add_name_server(NameServerConfig {
                    socket_addr,
                    protocol: Protocol::Tcp,
                    tls_dns_name: None,
                    trust_nx_responses: false,
                    #[cfg(any(feature = "dns-over-tls", feature = "dns-over-https"))]
                    tls_config: None,
                    bind_addr: None,
                });
            }
        }

        Ok(if c.name_servers().is_empty() {
            DnsConfig::System
        } else {
            DnsConfig::TrustDns(c)
        })
    }

    #[cfg(not(any(feature = "trust-dns", feature = "local-dns")))]
    fn parse_dns_nameservers(&mut self, _nameservers: &str) -> Result<DnsConfig, Error> {
        Ok(DnsConfig::System)
    }

    /// Load Config from a `str`
    pub fn load_from_str(s: &str, config_type: ConfigType) -> Result<Config, Error> {
        let c = json5::from_str::<SSConfig>(s)?;
        Config::load_from_ssconfig(c, config_type)
    }

    /// Load Config from a File
    pub fn load_from_file<P: AsRef<Path>>(filename: P, config_type: ConfigType) -> Result<Config, Error> {
        let filename = filename.as_ref();

        let mut reader = OpenOptions::new().read(true).open(filename)?;
        let mut content = String::new();
        reader.read_to_string(&mut content)?;

        let mut config = Config::load_from_str(&content[..], config_type)?;

        // Record the path of the configuration for auto-reloading
        config.config_path = Some(filename.to_owned());

        Ok(config)
    }

    /// Check if there are any plugin are enabled with servers
    pub fn has_server_plugins(&self) -> bool {
        for inst in &self.server {
            let server = &inst.config;

            if server.plugin().is_some() {
                return true;
            }
        }
        false
    }

    /// Check if all required fields are already set
    pub fn check_integrity(&self) -> Result<(), Error> {
        if self.config_type.is_local() {
            if self.local.is_empty() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing `locals` for client configuration",
                    None,
                );
                return Err(err);
            }

            for local_config in &self.local {
                local_config.config.check_integrity()?;
            }

            // Balancer related checks
            if let Some(rtt) = self.balancer.max_server_rtt {
                if rtt.as_secs() == 0 {
                    let err = Error::new(ErrorKind::Invalid, "balancer.max_server_rtt must be > 0", None);
                    return Err(err);
                }
            }

            if let Some(intv) = self.balancer.check_interval {
                if intv.as_secs() == 0 {
                    let err = Error::new(ErrorKind::Invalid, "balancer.check_interval must be > 0", None);
                    return Err(err);
                }
            }
        }

        if self.config_type.is_server() && self.server.is_empty() {
            let err = Error::new(
                ErrorKind::MissingField,
                "missing any valid servers in configuration",
                None,
            );
            return Err(err);
        }

        if self.config_type.is_manager() && self.manager.is_none() {
            let err = Error::new(
                ErrorKind::MissingField,
                "missing `manager_addr` and `manager_port` in configuration",
                None,
            );
            return Err(err);
        }

        for inst in &self.server {
            let server = &inst.config;

            // Plugin shouldn't be an empty string
            if let Some(plugin) = server.plugin() {
                if plugin.plugin.trim().is_empty() {
                    let err = Error::new(ErrorKind::Malformed, "`plugin` shouldn't be an empty string", None);
                    return Err(err);
                }
            }

            // Server's domain name shouldn't be an empty string
            match server.addr() {
                ServerAddr::SocketAddr(sa) => {
                    if sa.port() == 0 {
                        let err = Error::new(ErrorKind::Malformed, "`server_port` shouldn't be 0", None);
                        return Err(err);
                    }

                    if self.config_type.is_local() {
                        // Only server could bind to INADDR_ANY
                        let ip = sa.ip();
                        if ip.is_unspecified() {
                            let err = Error::new(
                                ErrorKind::Malformed,
                                "`server` shouldn't be an unspecified address (INADDR_ANY)",
                                None,
                            );
                            return Err(err);
                        }
                    }
                }
                ServerAddr::DomainName(dn, port) => {
                    if dn.is_empty() || *port == 0 {
                        let err = Error::new(
                            ErrorKind::Malformed,
                            "`server` shouldn't be an empty string, `server_port` shouldn't be 0",
                            None,
                        );
                        return Err(err);
                    }
                }
            }

            // Users' key must match key length
            if let Some(user_manager) = server.user_manager() {
                let key_len = server.method().key_len();
                for user in user_manager.users_iter() {
                    if user.key().len() != key_len {
                        let err = Error::new(
                            ErrorKind::Malformed,
                            "`users[].password` length must be exactly the same as method's key length",
                            None,
                        );
                        return Err(err);
                    }
                }
            }
        }

        Ok(())
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Convert to json

        let mut jconf = SSConfig::default();

        // Locals
        if !self.local.is_empty() {
            if self.local.len() == 1 && self.local[0].config.is_basic() {
                let local_instance = &self.local[0];
                let local = &local_instance.config;
                if let Some(ref a) = local.addr {
                    jconf.local_address = Some(match a {
                        ServerAddr::SocketAddr(ref sa) => sa.ip().to_string(),
                        ServerAddr::DomainName(ref dm, ..) => dm.to_string(),
                    });
                    jconf.local_port = Some(match a {
                        ServerAddr::SocketAddr(ref sa) => sa.port(),
                        ServerAddr::DomainName(.., port) => *port,
                    });
                }

                if local.protocol != ProtocolType::Socks {
                    jconf.protocol = Some(local.protocol.as_str().to_owned());
                }

                // ACL
                if let Some(ref acl) = local_instance.acl {
                    jconf.acl = Some(acl.file_path().to_str().unwrap().to_owned());
                }
            } else {
                let mut jlocals = Vec::with_capacity(self.local.len());
                for local_instance in &self.local {
                    let local = &local_instance.config;

                    let jlocal = SSLocalExtConfig {
                        local_address: local.addr.as_ref().map(|a| match a {
                            ServerAddr::SocketAddr(ref sa) => sa.ip().to_string(),
                            ServerAddr::DomainName(ref dm, ..) => dm.to_string(),
                        }),
                        local_port: local.addr.as_ref().map(|a| match a {
                            ServerAddr::SocketAddr(ref sa) => sa.port(),
                            ServerAddr::DomainName(.., port) => *port,
                        }),
                        disabled: None,
                        local_udp_address: local.udp_addr.as_ref().map(|udp_addr| match udp_addr {
                            ServerAddr::SocketAddr(sa) => sa.ip().to_string(),
                            ServerAddr::DomainName(dm, ..) => dm.to_string(),
                        }),
                        local_udp_port: local.udp_addr.as_ref().map(|udp_addr| match udp_addr {
                            ServerAddr::SocketAddr(sa) => sa.port(),
                            ServerAddr::DomainName(.., port) => *port,
                        }),
                        mode: Some(local.mode.to_string()),
                        protocol: match local.protocol {
                            ProtocolType::Socks => None,
                            #[allow(unreachable_patterns)]
                            p => Some(p.as_str().to_owned()),
                        },
                        #[cfg(feature = "local-redir")]
                        tcp_redir: if local.tcp_redir != RedirType::tcp_default() {
                            Some(local.tcp_redir.to_string())
                        } else {
                            None
                        },
                        #[cfg(feature = "local-redir")]
                        udp_redir: if local.udp_redir != RedirType::udp_default() {
                            Some(local.udp_redir.to_string())
                        } else {
                            None
                        },
                        #[cfg(feature = "local-tunnel")]
                        forward_address: match local.forward_addr {
                            None => None,
                            Some(ref forward_addr) => match forward_addr {
                                Address::SocketAddress(ref sa) => Some(sa.ip().to_string()),
                                Address::DomainNameAddress(ref dm, ..) => Some(dm.to_string()),
                            },
                        },
                        #[cfg(feature = "local-tunnel")]
                        forward_port: match local.forward_addr {
                            None => None,
                            Some(ref forward_addr) => match forward_addr {
                                Address::SocketAddress(ref sa) => Some(sa.port()),
                                Address::DomainNameAddress(.., port) => Some(*port),
                            },
                        },
                        #[cfg(feature = "local-dns")]
                        local_dns_address: match local.local_dns_addr {
                            None => None,
                            Some(ref local_dns_addr) => match local_dns_addr {
                                NameServerAddr::SocketAddr(ref sa) => Some(sa.ip().to_string()),
                                #[cfg(unix)]
                                NameServerAddr::UnixSocketAddr(ref path) => {
                                    Some(path.to_str().expect("path is not utf-8").to_owned())
                                }
                            },
                        },
                        #[cfg(feature = "local-dns")]
                        local_dns_port: match local.local_dns_addr {
                            None => None,
                            Some(ref local_dns_addr) => match local_dns_addr {
                                NameServerAddr::SocketAddr(ref sa) => Some(sa.port()),
                                #[cfg(unix)]
                                NameServerAddr::UnixSocketAddr(..) => None,
                            },
                        },
                        #[cfg(feature = "local-dns")]
                        remote_dns_address: match local.remote_dns_addr {
                            None => None,
                            Some(ref remote_dns_addr) => match remote_dns_addr {
                                Address::SocketAddress(ref sa) => Some(sa.ip().to_string()),
                                Address::DomainNameAddress(ref dm, ..) => Some(dm.to_string()),
                            },
                        },
                        #[cfg(feature = "local-dns")]
                        remote_dns_port: match local.remote_dns_addr {
                            None => None,
                            Some(ref remote_dns_addr) => match remote_dns_addr {
                                Address::SocketAddress(ref sa) => Some(sa.port()),
                                Address::DomainNameAddress(.., port) => Some(*port),
                            },
                        },
                        #[cfg(feature = "local-tun")]
                        tun_interface_name: local.tun_interface_name.clone(),
                        #[cfg(feature = "local-tun")]
                        tun_interface_address: local.tun_interface_address.as_ref().map(ToString::to_string),
                        #[cfg(feature = "local-tun")]
                        tun_interface_destination: local.tun_interface_destination.as_ref().map(ToString::to_string),
                        #[cfg(all(feature = "local-tun", unix))]
                        tun_device_fd_from_path: local
                            .tun_device_fd_from_path
                            .as_ref()
                            .map(|p| p.to_str().expect("tun_device_fd_from_path is not utf-8").to_owned()),

                        #[cfg(feature = "local")]
                        socks5_auth_config_path: None,

                        acl: local_instance
                            .acl
                            .as_ref()
                            .and_then(|a| a.file_path().to_str().map(ToOwned::to_owned)),
                    };
                    jlocals.push(jlocal);
                }
                jconf.locals = Some(jlocals);
            }
        }

        // Servers
        match self.server.len() {
            0 => {}
            // For 1 server, uses standard configure format
            1 if self.server[0].config.is_basic() => {
                let inst = &self.server[0];
                let svr = &inst.config;

                jconf.server = Some(match *svr.addr() {
                    ServerAddr::SocketAddr(ref sa) => sa.ip().to_string(),
                    ServerAddr::DomainName(ref dm, ..) => dm.to_string(),
                });
                jconf.server_port = Some(match *svr.addr() {
                    ServerAddr::SocketAddr(ref sa) => sa.port(),
                    ServerAddr::DomainName(.., port) => port,
                });
                jconf.method = Some(svr.method().to_string());
                jconf.password = if svr.method().is_none() {
                    None
                } else {
                    Some(svr.password().to_string())
                };
                jconf.plugin = svr.plugin().map(|p| p.plugin.to_string());
                jconf.plugin_opts = svr.plugin().and_then(|p| p.plugin_opts.clone());
                jconf.plugin_args = svr.plugin().and_then(|p| {
                    if p.plugin_args.is_empty() {
                        None
                    } else {
                        Some(p.plugin_args.clone())
                    }
                });
                jconf.timeout = svr.timeout().map(|t| t.as_secs());
                jconf.mode = Some(svr.mode().to_string());

                if let Some(ref acl) = inst.acl {
                    jconf.acl = Some(acl.file_path().to_str().unwrap().to_owned());
                }
            }
            // For >1 servers, uses extended multiple server format
            _ => {
                let mut vsvr = Vec::new();

                for inst in &self.server {
                    let svr = &inst.config;

                    vsvr.push(SSServerExtConfig {
                        server: match *svr.addr() {
                            ServerAddr::SocketAddr(ref sa) => sa.ip().to_string(),
                            ServerAddr::DomainName(ref dm, ..) => dm.to_string(),
                        },
                        server_port: match *svr.addr() {
                            ServerAddr::SocketAddr(ref sa) => sa.port(),
                            ServerAddr::DomainName(.., port) => port,
                        },
                        password: if svr.method().is_none() {
                            None
                        } else {
                            Some(svr.password().to_string())
                        },
                        method: svr.method().to_string(),
                        users: svr.user_manager().map(|m| {
                            let mut vu = Vec::new();
                            for u in m.users_iter() {
                                vu.push(SSServerUserConfig {
                                    name: u.name().to_owned(),
                                    password: u.encoded_key(),
                                });
                            }
                            vu
                        }),
                        disabled: None,
                        plugin: svr.plugin().map(|p| p.plugin.to_string()),
                        plugin_opts: svr.plugin().and_then(|p| p.plugin_opts.clone()),
                        plugin_args: svr.plugin().and_then(|p| {
                            if p.plugin_args.is_empty() {
                                None
                            } else {
                                Some(p.plugin_args.clone())
                            }
                        }),
                        timeout: svr.timeout().map(|t| t.as_secs()),
                        remarks: svr.remarks().map(ToOwned::to_owned),
                        id: svr.id().map(ToOwned::to_owned),
                        mode: Some(svr.mode().to_string()),
                        tcp_weight: if (svr.weight().tcp_weight() - 1.0).abs() > f32::EPSILON {
                            Some(svr.weight().tcp_weight())
                        } else {
                            None
                        },
                        udp_weight: if (svr.weight().udp_weight() - 1.0).abs() > f32::EPSILON {
                            Some(svr.weight().udp_weight())
                        } else {
                            None
                        },
                        acl: inst
                            .acl
                            .as_ref()
                            .and_then(|a| a.file_path().to_str().map(ToOwned::to_owned)),
                    });
                }

                jconf.servers = Some(vsvr);
            }
        }

        if let Some(ref m) = self.manager {
            jconf.manager_address = Some(match m.addr {
                ManagerAddr::SocketAddr(ref saddr) => saddr.ip().to_string(),
                ManagerAddr::DomainName(ref dname, ..) => dname.clone(),
                #[cfg(unix)]
                ManagerAddr::UnixSocketAddr(ref path) => path.display().to_string(),
            });

            jconf.manager_port = match m.addr {
                ManagerAddr::SocketAddr(ref saddr) => Some(saddr.port()),
                ManagerAddr::DomainName(.., port) => Some(port),
                #[cfg(unix)]
                ManagerAddr::UnixSocketAddr(..) => None,
            };

            if jconf.mode.is_none() {
                jconf.mode = Some(m.mode.to_string());
            }

            if jconf.method.is_none() {
                if let Some(ref m) = m.method {
                    jconf.method = Some(m.to_string());
                }
            }

            if jconf.plugin.is_none() {
                if let Some(ref p) = m.plugin {
                    jconf.plugin = Some(p.plugin.clone());
                    if let Some(ref o) = p.plugin_opts {
                        jconf.plugin_opts = Some(o.clone());
                    }
                    if !p.plugin_args.is_empty() {
                        jconf.plugin_args = Some(p.plugin_args.clone());
                    }
                }
            }
        }

        if self.no_delay {
            jconf.no_delay = Some(self.no_delay);
        }

        if self.fast_open {
            jconf.fast_open = Some(self.fast_open);
        }

        if let Some(keepalive) = self.keep_alive {
            jconf.keep_alive = Some(keepalive.as_secs());
        }

        match self.dns {
            DnsConfig::System => {}
            #[cfg(feature = "trust-dns")]
            DnsConfig::TrustDns(ref dns) => {
                jconf.dns = Some(SSDnsConfig::TrustDns(dns.clone()));
            }
            #[cfg(feature = "local-dns")]
            DnsConfig::LocalDns(ref ns) => {
                jconf.dns = Some(SSDnsConfig::Simple(ns.to_string()));
            }
        }

        jconf.udp_timeout = self.udp_timeout.map(|t| t.as_secs());

        jconf.udp_max_associations = self.udp_max_associations;

        #[cfg(all(unix, not(target_os = "android")))]
        {
            jconf.nofile = self.nofile;
        }

        if self.ipv6_first {
            jconf.ipv6_first = Some(self.ipv6_first);
        }

        if self.ipv6_only {
            jconf.ipv6_only = Some(self.ipv6_only);
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            jconf.outbound_fwmark = self.outbound_fwmark;
        }

        #[cfg(target_os = "freebsd")]
        {
            jconf.outbound_user_cookie = self.outbound_user_cookie;
        }

        jconf.outbound_bind_addr = self.outbound_bind_addr.map(|i| i.to_string());
        jconf.outbound_bind_interface = self.outbound_bind_interface.clone();

        // Security
        if self.security.replay_attack.policy != ReplayAttackPolicy::default() {
            jconf.security = Some(SSSecurityConfig {
                replay_attack: Some(SSSecurityReplayAttackConfig {
                    policy: Some(self.security.replay_attack.policy.to_string()),
                }),
            });
        }

        // Balancer
        if self.balancer.max_server_rtt.is_some() || self.balancer.check_interval.is_some() {
            jconf.balancer = Some(SSBalancerConfig {
                max_server_rtt: self.balancer.max_server_rtt.as_ref().map(Duration::as_secs),
                check_interval: self.balancer.check_interval.as_ref().map(Duration::as_secs),
                check_best_interval: self.balancer.check_best_interval.as_ref().map(Duration::as_secs),
            });
        }

        // ACL
        if let Some(ref acl) = self.acl {
            jconf.acl = Some(acl.file_path().to_str().unwrap().to_owned());
        }

        write!(f, "{}", json5::to_string(&jconf).unwrap())
    }
}

/// Parse variable value if it is an environment variable
///
/// If value is in format `${VAR_NAME}` then it will try to read from `VAR_NAME` environment variable.
/// It will return the original value if fails to read `${VAR_NAME}`.
pub fn read_variable_field_value(value: &str) -> Cow<'_, str> {
    if let Some(left_over) = value.strip_prefix("${") {
        if let Some(var_name) = left_over.strip_suffix('}') {
            match env::var(var_name) {
                Ok(value) => return value.into(),
                Err(err) => {
                    warn!(
                        "couldn't read password from environemnt variable {}, error: {}",
                        var_name, err
                    );
                }
            }
        }
    }

    value.into()
}
