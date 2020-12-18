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

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::ffi::OsString;
use std::{
    convert::{From, Infallible},
    default::Default,
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
use serde::{Deserialize, Serialize};
#[cfg(feature = "local-tunnel")]
use shadowsocks::relay::socks5::Address;
use shadowsocks::{
    config::{ManagerAddr, ServerAddr, ServerConfig},
    crypto::v1::CipherKind,
    plugin::PluginConfig,
};
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig};

use crate::local::acl::AccessControl;
#[cfg(feature = "local-dns")]
pub use crate::local::dns::config::NameServerAddr;

#[cfg(feature = "trust-dns")]
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum SSDnsConfig {
    Simple(String),
    TrustDns(ResolverConfig),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    servers: Option<Vec<SSServerExtConfig>>,
    #[cfg(feature = "trust-dns")]
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<SSDnsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_delay: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nofile: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6_first: Option<bool>,
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
    password: String,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_opts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remarks: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

/// Listening address
pub type ClientConfig = ServerAddr;

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

/// Server mode
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    TcpOnly,
    TcpAndUdp,
    UdpOnly,
}

impl Mode {
    pub fn enable_udp(self) -> bool {
        matches!(self, Mode::UdpOnly | Mode::TcpAndUdp)
    }

    pub fn enable_tcp(self) -> bool {
        matches!(self, Mode::TcpOnly | Mode::TcpAndUdp)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Mode::TcpOnly => f.write_str("tcp_only"),
            Mode::TcpAndUdp => f.write_str("tcp_and_udp"),
            Mode::UdpOnly => f.write_str("udp_only"),
        }
    }
}

impl FromStr for Mode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp_only" => Ok(Mode::TcpOnly),
            "tcp_and_udp" => Ok(Mode::TcpAndUdp),
            "udp_only" => Ok(Mode::UdpOnly),
            _ => Err(()),
        }
    }
}

cfg_if! {
    if #[cfg(feature = "local-redir")] {
        use strum::IntoEnumIterator;
        use strum_macros::EnumIter;

        /// Transparent Proxy type
        #[derive(Clone, Copy, Debug, Eq, PartialEq, EnumIter)]
        pub enum RedirType {
            /// For not supported platforms
            NotSupported,

            /// For Linux-like systems' Netfilter `REDIRECT`. Only for TCP connections.
            ///
            /// This is supported from Linux 2.4 Kernel. Document: https://www.netfilter.org/documentation/index.html#documentation-howto
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
            /// Document: https://www.freebsd.org/doc/handbook/firewalls-pf.html
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
                    pub fn tcp_default() -> RedirType {
                        RedirType::Redirect
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub fn udp_default() -> RedirType {
                        RedirType::TProxy
                    }
                } else if #[cfg(any(target_os = "openbsd", target_os = "freebsd"))] {
                    /// Default TCP transparent proxy solution on this platform
                    pub fn tcp_default() -> RedirType {
                        RedirType::PacketFilter
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub fn udp_default() -> RedirType {
                        RedirType::PacketFilter
                    }
                } else if #[cfg(any(target_os = "netbsd", target_os = "solaris", target_os = "macos", target_os = "ios"))] {
                    /// Default TCP transparent proxy solution on this platform
                    pub fn tcp_default() -> RedirType {
                        RedirType::PacketFilter
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub fn udp_default() -> RedirType {
                        RedirType::NotSupported
                    }
                } else {
                    /// Default TCP transparent proxy solution on this platform
                    pub fn tcp_default() -> RedirType {
                        RedirType::NotSupported
                    }

                    /// Default UDP transparent proxy solution on this platform
                    pub fn udp_default() -> RedirType {
                        RedirType::NotSupported
                    }
                }
            }

            /// Check if transparent proxy is supported on this platform
            pub fn is_supported(self) -> bool {
                self != RedirType::NotSupported
            }

            /// Name of redirect type (transparent proxy type)
            pub fn name(self) -> &'static str {
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

            /// Get all available types
            pub fn available_types() -> Vec<&'static str> {
                let mut v = Vec::new();
                for e in Self::iter() {
                    match e {
                        RedirType::NotSupported => continue,
                        #[allow(unreachable_patterns)]
                        _ => v.push(e.name()),
                    }
                }
                v
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

/// Configuration for Manager
#[derive(Clone, Debug)]
pub struct ManagerConfig {
    /// Address of `ss-manager`. Send servers' statistic data to the manager server
    pub addr: ManagerAddr,
    /// Manager's default method
    pub method: Option<CipherKind>,
    /// Timeout for TCP connections, setting to manager's created servers
    pub timeout: Option<Duration>,
    /// IP/Host for servers to bind (inbound)
    ///
    /// Note: Outbound address is defined in Config.local_addr
    pub server_host: ManagerServerHost,
}

impl ManagerConfig {
    /// Create a ManagerConfig with default options
    pub fn new(addr: ManagerAddr) -> ManagerConfig {
        ManagerConfig {
            addr,
            method: None,
            timeout: None,
            server_host: ManagerServerHost::default(),
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
        ]
    }
}

/// Error while parsing `ProtocolType` from string
#[derive(Debug)]
pub struct ProtocolTypeError;

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
            _ => Err(ProtocolTypeError),
        }
    }
}

/// Configuration
#[derive(Clone, Debug)]
pub struct Config {
    /// Remote ShadowSocks server configurations
    pub server: Vec<ServerConfig>,
    /// Local server's bind address, or ShadowSocks server's outbound address
    pub local_addr: Option<ClientConfig>,
    /// Destination address for tunnel
    #[cfg(feature = "local-tunnel")]
    pub forward: Option<Address>,
    /// DNS configuration, uses system-wide DNS configuration by default
    ///
    /// Value could be a `IpAddr`, uses UDP DNS protocol with port `53`. For example: `8.8.8.8`
    ///
    /// Also Value could be some pre-defined DNS server names:
    ///
    /// - `google`
    /// - `cloudflare`, `cloudflare_tls`, `cloudflare_https`
    /// - `quad9`, `quad9_tls`
    #[cfg(feature = "trust-dns")]
    pub dns: Option<ResolverConfig>,
    /// Server mode, `tcp_only`, `tcp_and_udp`, and `udp_only`
    pub mode: Mode,
    /// Set `TCP_NODELAY` socket option
    pub no_delay: bool,
    /// Set `SO_MARK` socket option for outbound sockets
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub outbound_fwmark: Option<u32>,
    /// Set `SO_BINDTODEVICE` socket option for outbound sockets
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub outbound_bind_interface: Option<OsString>,
    /// Manager's configuration
    pub manager: Option<ManagerConfig>,
    /// Config is for Client or Server
    pub config_type: ConfigType,
    /// Protocol for local server
    pub local_protocol: ProtocolType,
    /// Timeout for UDP Associations, default is 5 minutes
    pub udp_timeout: Option<Duration>,
    /// Maximum number of UDP Associations, default is unconfigured
    pub udp_max_associations: Option<usize>,
    /// UDP relay's bind address, it uses `local_addr` by default
    ///
    /// Resolving Android's issue: [shadowsocks/shadowsocks-android#2571](https://github.com/shadowsocks/shadowsocks-android/issues/2571)
    pub udp_bind_addr: Option<ClientConfig>,
    /// `RLIMIT_NOFILE` option for *nix systems
    pub nofile: Option<u64>,
    /// ACL configuration
    pub acl: Option<AccessControl>,
    /// TCP Transparent Proxy type
    #[cfg(feature = "local-redir")]
    pub tcp_redir: RedirType,
    /// UDP Transparent Proxy type
    #[cfg(feature = "local-redir")]
    pub udp_redir: RedirType,
    /// Flow statistic report Unix socket path (only for Android)
    #[cfg(feature = "local-flow-stat")]
    pub stat_path: Option<PathBuf>,
    /// Path to protect callback unix address, only for Android
    #[cfg(target_os = "android")]
    pub outbound_vpn_protect_path: Option<PathBuf>,
    /// Internal DNS's bind address
    #[cfg(feature = "local-dns")]
    pub dns_bind_addr: Option<ClientConfig>,
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
    /// Uses IPv6 addresses first
    ///
    /// Set to `true` if you want to query IPv6 addresses before IPv4
    pub ipv6_first: bool,
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
            local_addr: None,
            #[cfg(feature = "local-tunnel")]
            forward: None,
            #[cfg(feature = "trust-dns")]
            dns: None,
            mode: Mode::TcpOnly,
            no_delay: false,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            outbound_fwmark: None,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            outbound_bind_interface: None,
            manager: None,
            config_type,
            local_protocol: ProtocolType::default(),
            udp_timeout: None,
            udp_max_associations: None,
            udp_bind_addr: None,
            nofile: None,
            acl: None,
            #[cfg(feature = "local-redir")]
            tcp_redir: RedirType::tcp_default(),
            #[cfg(feature = "local-redir")]
            udp_redir: RedirType::udp_default(),
            #[cfg(feature = "local-flow-stat")]
            stat_path: None,
            #[cfg(target_os = "android")]
            outbound_vpn_protect_path: None,
            #[cfg(feature = "local-dns")]
            dns_bind_addr: None,
            #[cfg(feature = "local-dns")]
            local_dns_addr: None,
            #[cfg(feature = "local-dns")]
            remote_dns_addr: None,
            ipv6_first: false,
        }
    }

    fn load_from_ssconfig(config: SSConfig, config_type: ConfigType) -> Result<Config, Error> {
        let mut nconfig = Config::new(config_type);

        // Standard config
        // Client
        //
        // local_address is allowed to be NULL, which means to bind to ::1 or 127.0.0.1
        //
        // https://shadowsocks.org/en/config/quick-guide.html
        match config.local_address {
            Some(la) => {
                let local_port = if config_type.is_local() {
                    let local_port = config.local_port.unwrap_or(0);
                    if local_port == 0 {
                        let err = Error::new(ErrorKind::MissingField, "missing `local_port`", None);
                        return Err(err);
                    }
                    local_port
                } else if config_type.is_server() || config_type.is_manager() {
                    // server's local_port is ignored
                    0
                } else {
                    config.local_port.unwrap_or(0)
                };

                let local_addr = match la.parse::<IpAddr>() {
                    Ok(ip) => ServerAddr::from(SocketAddr::new(ip, local_port)),
                    Err(..) => {
                        // treated as domain
                        ServerAddr::from((la, local_port))
                    }
                };
                nconfig.local_addr = Some(local_addr);
            }
            None => {
                if config_type.is_local() && config.local_port.is_some() {
                    // Implementation note: This is not implemented like libev which will choose IPv6 or IPv6 LoopBack address
                    // by checking all its remote servers if all of them supports IPv6.
                    let ip = if config.ipv6_first.unwrap_or(false) {
                        Ipv6Addr::LOCALHOST.into()
                    } else {
                        Ipv4Addr::LOCALHOST.into()
                    };

                    let local_port = config.local_port.unwrap_or(0);
                    if local_port == 0 {
                        let err = Error::new(ErrorKind::MissingField, "`local_port` shouldn't be 0", None);
                        return Err(err);
                    }

                    let local_addr = ServerAddr::from(SocketAddr::new(ip, local_port));
                    nconfig.local_addr = Some(local_addr);
                }
            }
        };

        // Standard config
        // Server
        match (config.server, config.server_port, config.password, config.method) {
            (Some(address), Some(port), Some(pwd), Some(m)) => {
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
                            Some(format!("`{}` is not a supported method", m)),
                        );
                        return Err(err);
                    }
                };

                let mut nsvr = ServerConfig::new(addr, pwd, method);

                if let Some(p) = config.plugin {
                    // SIP008 allows "plugin" to be an empty string
                    // Empty string implies "no plugin"
                    if !p.is_empty() {
                        let plugin = PluginConfig {
                            plugin: p,
                            plugin_opts: config.plugin_opts,
                            plugin_args: config.plugin_args.unwrap_or_default(),
                        };
                        nsvr.set_plugin(plugin);
                    }
                }

                if let Some(timeout) = config.timeout.map(Duration::from_secs) {
                    nsvr.set_timeout(timeout);
                }

                nconfig.server.push(nsvr);
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

                let mut nsvr = ServerConfig::new(addr, svr.password, method);

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

                nconfig.server.push(nsvr);
            }
        }

        // Set timeout globally
        if let Some(timeout) = config.timeout {
            let timeout = Duration::from_secs(timeout);
            // Set as a default timeout
            for svr in &mut nconfig.server {
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

            let manager_config = ManagerConfig::new(manager);
            nconfig.manager = Some(manager_config);
        }

        // DNS
        #[cfg(feature = "trust-dns")]
        {
            nconfig.dns = match config.dns {
                Some(SSDnsConfig::Simple(ds)) => {
                    match &ds[..] {
                        "google" => Some(ResolverConfig::google()),

                        "cloudflare" => Some(ResolverConfig::cloudflare()),
                        #[cfg(feature = "dns-over-tls")]
                        "cloudflare_tls" => Some(ResolverConfig::cloudflare_tls()),
                        #[cfg(feature = "dns-over-https")]
                        "cloudflare_https" => Some(ResolverConfig::cloudflare_https()),

                        "quad9" => Some(ResolverConfig::quad9()),
                        #[cfg(feature = "dns-over-tls")]
                        "quad9_tls" => Some(ResolverConfig::quad9_tls()),

                        nameservers => {
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
                                        "invalid `dns` value, can only be host[:port][,host[:port]]...",
                                        None,
                                    );
                                    return Err(e);
                                };

                                c.add_name_server(NameServerConfig {
                                    socket_addr,
                                    protocol: Protocol::Udp,
                                    tls_dns_name: None,
                                    trust_nx_responses: false,
                                    #[cfg(feature = "dns-over-tls")]
                                    tls_config: None,
                                });
                                c.add_name_server(NameServerConfig {
                                    socket_addr,
                                    protocol: Protocol::Tcp,
                                    tls_dns_name: None,
                                    trust_nx_responses: false,
                                    #[cfg(feature = "dns-over-tls")]
                                    tls_config: None,
                                });
                            }

                            if c.name_servers().is_empty() {
                                None
                            } else {
                                Some(c)
                            }
                        }
                    }
                }
                Some(SSDnsConfig::TrustDns(c)) => Some(c),
                None => None,
            };
        }

        // Mode
        if let Some(m) = config.mode {
            match m.parse::<Mode>() {
                Ok(xm) => nconfig.mode = xm,
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

        // TCP nodelay
        if let Some(b) = config.no_delay {
            nconfig.no_delay = b;
        }

        // UDP
        nconfig.udp_timeout = config.udp_timeout.map(Duration::from_secs);

        // Maximum associations to be kept simultaneously
        nconfig.udp_max_associations = config.udp_max_associations;

        // RLIMIT_NOFILE
        nconfig.nofile = config.nofile;

        // Uses IPv6 first
        if let Some(f) = config.ipv6_first {
            nconfig.ipv6_first = f;
        }

        Ok(nconfig)
    }

    /// Load Config from a `str`
    pub fn load_from_str(s: &str, config_type: ConfigType) -> Result<Config, Error> {
        let c = json5::from_str::<SSConfig>(s)?;
        Config::load_from_ssconfig(c, config_type)
    }

    /// Load Config from a File
    pub fn load_from_file(filename: &str, config_type: ConfigType) -> Result<Config, Error> {
        let mut reader = OpenOptions::new().read(true).open(&Path::new(filename))?;
        let mut content = String::new();
        reader.read_to_string(&mut content)?;
        Config::load_from_str(&content[..], config_type)
    }

    /// Check if there are any plugin are enabled with servers
    pub fn has_server_plugins(&self) -> bool {
        for server in &self.server {
            if server.plugin().is_some() {
                return true;
            }
        }
        false
    }

    /// Check if all required fields are already set
    pub fn check_integrity(&self) -> Result<(), Error> {
        if self.config_type.is_local() {
            match self.local_addr {
                None => {
                    let err = Error::new(
                        ErrorKind::MissingField,
                        "missing `local_address` and `local_port` for client configuration",
                        None,
                    );
                    return Err(err);
                }
                Some(ref addr) => {
                    if addr.port() == 0 {
                        let err = Error::new(
                            ErrorKind::Malformed,
                            "`local_port` couldn't be 0 for client configuration",
                            None,
                        );
                        return Err(err);
                    }
                }
            }

            if self.server.is_empty() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing `servers` for client configuration",
                    None,
                );
                return Err(err);
            }
        }

        if self.config_type.is_server() {
            if self.server.is_empty() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing any valid servers in configuration",
                    None,
                );
                return Err(err);
            }

            if let Some(ref addr) = self.local_addr {
                if addr.port() != 0 {
                    let err = Error::new(
                        ErrorKind::Malformed,
                        "`local_port` must be 0 for server configuration",
                        None,
                    );
                    return Err(err);
                }
            }
        }

        if self.config_type.is_manager() {
            if self.manager.is_none() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing `manager_addr` and `manager_port` in configuration",
                    None,
                );
                return Err(err);
            }

            if let Some(ref addr) = self.local_addr {
                if addr.port() != 0 {
                    let err = Error::new(
                        ErrorKind::Malformed,
                        "`local_port` must be 0 for server configuration",
                        None,
                    );
                    return Err(err);
                }
            }
        }

        for server in &self.server {
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
        }

        if self.local_protocol == ProtocolType::Socks && !self.mode.enable_tcp() {
            let err = Error::new(ErrorKind::Malformed, "socks protocol must enable tcp mode", None);
            return Err(err);
        }

        #[cfg(feature = "local-dns")]
        if self.local_protocol == ProtocolType::Dns {
            if self.dns_bind_addr.is_none() || self.local_dns_addr.is_none() || self.remote_dns_addr.is_none() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing `dns_bind_addr`, `local_dns_addr` or `remote_dns_addr` in configuration",
                    None,
                );
                return Err(err);
            }
        } else if self.dns_bind_addr.is_some() {
            // Run a DNS server in the same process
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
        if self.local_protocol == ProtocolType::Tunnel {
            if self.forward.is_none() {
                let err = Error::new(ErrorKind::MissingField, "missing `forward` in configuration", None);
                return Err(err);
            }
        }

        Ok(())
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Convert to json

        let mut jconf = SSConfig::default();

        if let Some(ref client) = self.local_addr {
            match *client {
                ServerAddr::SocketAddr(ref sa) => {
                    jconf.local_address = Some(sa.ip().to_string());
                    jconf.local_port = Some(sa.port());
                }
                ServerAddr::DomainName(ref dname, port) => {
                    jconf.local_address = Some(dname.to_owned());
                    jconf.local_port = Some(port);
                }
            }
        }

        // Servers
        // For 1 servers, uses standard configure format
        match self.server.len() {
            0 => {}
            1 if self.server[0].id().is_none() && self.server[0].remarks().is_none() => {
                let svr = &self.server[0];

                jconf.server = Some(match *svr.addr() {
                    ServerAddr::SocketAddr(ref sa) => sa.ip().to_string(),
                    ServerAddr::DomainName(ref dm, ..) => dm.to_string(),
                });
                jconf.server_port = Some(match *svr.addr() {
                    ServerAddr::SocketAddr(ref sa) => sa.port(),
                    ServerAddr::DomainName(.., port) => port,
                });
                jconf.method = Some(svr.method().to_string());
                jconf.password = Some(svr.password().to_string());
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
            }
            _ => {
                let mut vsvr = Vec::new();

                for svr in &self.server {
                    vsvr.push(SSServerExtConfig {
                        server: match *svr.addr() {
                            ServerAddr::SocketAddr(ref sa) => sa.ip().to_string(),
                            ServerAddr::DomainName(ref dm, ..) => dm.to_string(),
                        },
                        server_port: match *svr.addr() {
                            ServerAddr::SocketAddr(ref sa) => sa.port(),
                            ServerAddr::DomainName(.., port) => port,
                        },
                        password: svr.password().to_string(),
                        method: svr.method().to_string(),
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
        }

        jconf.mode = Some(self.mode.to_string());

        if self.no_delay {
            jconf.no_delay = Some(self.no_delay);
        }

        #[cfg(feature = "trust-dns")]
        if let Some(ref dns) = self.dns {
            jconf.dns = Some(SSDnsConfig::TrustDns(dns.clone()));
        }

        jconf.udp_timeout = self.udp_timeout.map(|t| t.as_secs());

        jconf.udp_max_associations = self.udp_max_associations;

        jconf.nofile = self.nofile;

        if self.ipv6_first {
            jconf.ipv6_first = Some(self.ipv6_first);
        }

        write!(f, "{}", json5::to_string(&jconf).unwrap())
    }
}
