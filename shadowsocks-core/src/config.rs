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
    convert::{From, Infallible},
    default::Default,
    error,
    fmt::{self, Debug, Display, Formatter},
    fs::OpenOptions,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    option::Option,
    path::{Path, PathBuf},
    str::FromStr,
    string::ToString,
    time::Duration,
};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use bytes::Bytes;
use cfg_if::cfg_if;
use log::error;
use serde::{Deserialize, Serialize};
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig};
use url::{self, Url};

use crate::{
    acl::AccessControl,
    context::Context,
    crypto::v1::{openssl_bytes_to_key, CipherKind},
    plugin::PluginConfig,
    relay::{dns_resolver::resolve_bind_addr, socks5::Address},
};

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

/// Server address
#[derive(Clone, Debug)]
pub enum ServerAddr {
    /// IP Address
    SocketAddr(SocketAddr),
    /// Domain name address, eg. example.com:8080
    DomainName(String, u16),
}

impl ServerAddr {
    /// Get string representation of domain
    pub fn host(&self) -> String {
        match *self {
            ServerAddr::SocketAddr(ref s) => s.ip().to_string(),
            ServerAddr::DomainName(ref dm, _) => dm.clone(),
        }
    }

    /// Get port
    pub fn port(&self) -> u16 {
        match *self {
            ServerAddr::SocketAddr(ref s) => s.port(),
            ServerAddr::DomainName(_, p) => p,
        }
    }

    /// Convert for calling `bind()`
    pub async fn bind_addr(&self, context: &Context) -> io::Result<SocketAddr> {
        match resolve_bind_addr(context, self).await {
            Ok(s) => Ok(s),
            Err(err) => {
                error!("Failed to resolve {} for bind(), error: {}", self, err);
                Err(err)
            }
        }
    }
}

/// Parse `ServerAddr` error
#[derive(Debug)]
pub struct ServerAddrError;

impl FromStr for ServerAddr {
    type Err = ServerAddrError;

    fn from_str(s: &str) -> Result<ServerAddr, ServerAddrError> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(ServerAddr::SocketAddr(addr)),
            Err(..) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => match port.parse::<u16>() {
                        Ok(port) => Ok(ServerAddr::DomainName(dn.to_owned(), port)),
                        Err(..) => Err(ServerAddrError),
                    },
                    _ => Err(ServerAddrError),
                }
            }
        }
    }
}

impl Display for ServerAddr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            ServerAddr::SocketAddr(ref a) => write!(f, "{}", a),
            ServerAddr::DomainName(ref d, port) => write!(f, "{}:{}", d, port),
        }
    }
}

impl From<SocketAddr> for ServerAddr {
    fn from(addr: SocketAddr) -> ServerAddr {
        ServerAddr::SocketAddr(addr)
    }
}

impl<I: Into<String>> From<(I, u16)> for ServerAddr {
    fn from((dname, port): (I, u16)) -> ServerAddr {
        ServerAddr::DomainName(dname.into(), port)
    }
}

impl From<Address> for ServerAddr {
    fn from(addr: Address) -> ServerAddr {
        match addr {
            Address::SocketAddress(sa) => ServerAddr::SocketAddr(sa),
            Address::DomainNameAddress(dn, port) => ServerAddr::DomainName(dn, port),
        }
    }
}

impl From<&Address> for ServerAddr {
    fn from(addr: &Address) -> ServerAddr {
        match *addr {
            Address::SocketAddress(sa) => ServerAddr::SocketAddr(sa),
            Address::DomainNameAddress(ref dn, port) => ServerAddr::DomainName(dn.clone(), port),
        }
    }
}

impl From<ServerAddr> for Address {
    fn from(addr: ServerAddr) -> Address {
        match addr {
            ServerAddr::SocketAddr(sa) => Address::SocketAddress(sa),
            ServerAddr::DomainName(dn, port) => Address::DomainNameAddress(dn, port),
        }
    }
}

impl From<&ServerAddr> for Address {
    fn from(addr: &ServerAddr) -> Address {
        match *addr {
            ServerAddr::SocketAddr(sa) => Address::SocketAddress(sa),
            ServerAddr::DomainName(ref dn, port) => Address::DomainNameAddress(dn.clone(), port),
        }
    }
}

/// Configuration for a server
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Server address
    addr: ServerAddr,
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    method: CipherKind,
    /// Connection timeout
    timeout: Option<Duration>,
    // Encryption key
    enc_key: Bytes,

    /// Plugin config
    plugin: Option<PluginConfig>,
    /// Plugin address
    plugin_addr: Option<ServerAddr>,
    /// Remark (Profile Name), normally used as an identifier of this erver
    remarks: Option<String>,
    /// ID (SIP008) is a random generated UUID
    id: Option<String>,
}

impl ServerConfig {
    /// Creates a new ServerConfig
    pub fn new(
        addr: ServerAddr,
        password: String,
        method: CipherKind,
        timeout: Option<Duration>,
        plugin: Option<PluginConfig>,
    ) -> ServerConfig {
        let mut key = vec![0u8; method.key_len()];
        openssl_bytes_to_key(password.as_bytes(), &mut key);
        let enc_key = Bytes::copy_from_slice(&key);

        ServerConfig {
            addr,
            password,
            method,
            timeout,
            enc_key,
            plugin,
            plugin_addr: None,
            remarks: None,
            id: None,
        }
    }

    /// Create a basic config
    pub fn basic(addr: SocketAddr, password: String, method: CipherKind) -> ServerConfig {
        ServerConfig::new(ServerAddr::SocketAddr(addr), password, method, None, None)
    }

    /// Set encryption method
    pub fn set_method(&mut self, method: CipherKind, password: String) {
        self.method = method;

        let mut key = vec![0u8; method.key_len()];
        openssl_bytes_to_key(password.as_bytes(), &mut key);

        self.password = password;
        self.enc_key = Bytes::copy_from_slice(&key);
    }

    /// Set plugin
    pub fn set_plugin(&mut self, p: PluginConfig) {
        self.plugin = Some(p);
    }

    /// Set server addr
    pub fn set_addr(&mut self, a: ServerAddr) {
        self.addr = a;
    }

    /// Get server address
    pub fn addr(&self) -> &ServerAddr {
        &self.addr
    }

    /// Get encryption key
    pub fn key(&self) -> &[u8] {
        &self.enc_key[..]
    }

    /// Clone encryption key
    pub fn clone_key(&self) -> Bytes {
        self.enc_key.clone()
    }

    /// Get password
    pub fn password(&self) -> &str {
        &self.password[..]
    }

    /// Get method
    pub fn method(&self) -> CipherKind {
        self.method
    }

    /// Get timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Get plugin
    pub fn plugin(&self) -> Option<&PluginConfig> {
        self.plugin.as_ref()
    }

    /// Set plugin address
    pub fn set_plugin_addr(&mut self, a: ServerAddr) {
        self.plugin_addr = Some(a);
    }

    /// Get plugin address
    pub fn plugin_addr(&self) -> Option<&ServerAddr> {
        self.plugin_addr.as_ref()
    }

    /// Get server's external address
    pub fn external_addr(&self) -> &ServerAddr {
        self.plugin_addr.as_ref().unwrap_or(&self.addr)
    }

    /// Get server's remark
    pub fn remarks(&self) -> Option<&str> {
        self.remarks.as_ref().map(AsRef::as_ref)
    }

    /// Set server's remark
    pub fn set_remarks(&mut self, remarks: String) {
        self.remarks = Some(remarks);
    }

    /// Get server's ID (SIP008)
    pub fn id(&self) -> Option<&str> {
        self.id.as_ref().map(AsRef::as_ref)
    }

    /// Set server's ID (SIP008)
    pub fn set_id(&mut self, id: String) {
        self.id = Some(id)
    }

    /// Get URL for QRCode
    /// ```plain
    /// ss:// + base64(method:password@host:port)
    /// ```
    pub fn to_qrcode_url(&self) -> String {
        let param = format!("{}:{}@{}", self.method(), self.password(), self.addr());
        format!("ss://{}", encode_config(&param, URL_SAFE_NO_PAD))
    }

    /// Get [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    pub fn to_url(&self) -> String {
        let user_info = format!("{}:{}", self.method(), self.password());
        let encoded_user_info = encode_config(&user_info, URL_SAFE_NO_PAD);

        let mut url = format!("ss://{}@{}", encoded_user_info, self.addr());
        if let Some(c) = self.plugin() {
            let mut plugin = c.plugin.clone();
            if let Some(ref opt) = c.plugin_opts {
                plugin += ";";
                plugin += opt;
            }

            let plugin_param = [("plugin", &plugin)];
            url += "/?";
            url += &serde_urlencoded::to_string(&plugin_param).unwrap();
        }

        url
    }

    /// Parse from [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    pub fn from_url(encoded: &str) -> Result<ServerConfig, UrlParseError> {
        let parsed = Url::parse(encoded).map_err(UrlParseError::from)?;

        if parsed.scheme() != "ss" {
            return Err(UrlParseError::InvalidScheme);
        }

        let user_info = parsed.username();
        let account = match decode_config(user_info, URL_SAFE_NO_PAD) {
            Ok(account) => match String::from_utf8(account) {
                Ok(ac) => ac,
                Err(..) => {
                    return Err(UrlParseError::InvalidAuthInfo);
                }
            },
            Err(err) => {
                error!("Failed to parse UserInfo with Base64, err: {}", err);
                return Err(UrlParseError::InvalidUserInfo);
            }
        };

        let host = match parsed.host_str() {
            Some(host) => host,
            None => return Err(UrlParseError::MissingHost),
        };

        let port = parsed.port().unwrap_or(8388);
        let addr = format!("{}:{}", host, port);

        let mut sp2 = account.splitn(2, ':');
        let (method, pwd) = match (sp2.next(), sp2.next()) {
            (Some(m), Some(p)) => (m, p),
            _ => panic!("Malformed input"),
        };

        let addr = match addr.parse::<ServerAddr>() {
            Ok(a) => a,
            Err(err) => {
                error!("Failed to parse \"{}\" to ServerAddr, err: {:?}", addr, err);
                return Err(UrlParseError::InvalidServerAddr);
            }
        };

        let mut plugin = None;
        if let Some(q) = parsed.query() {
            let query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => q,
                Err(err) => {
                    error!("Failed to parse QueryString, err: {}", err);
                    return Err(UrlParseError::InvalidQueryString);
                }
            };

            for (key, value) in query {
                if key != "plugin" {
                    continue;
                }

                let mut vsp = value.splitn(2, ';');
                match vsp.next() {
                    None => {}
                    Some(p) => {
                        plugin = Some(PluginConfig {
                            plugin: p.to_owned(),
                            plugin_opts: vsp.next().map(ToOwned::to_owned),
                            plugin_args: Vec::new(), // SIP002 doesn't have arguments for plugins
                        })
                    }
                }
            }
        }

        let svrconfig = ServerConfig::new(addr, pwd.to_owned(), method.parse().unwrap(), None, plugin);

        Ok(svrconfig)
    }
}

impl FromStr for ServerConfig {
    type Err = UrlParseError;

    fn from_str(s: &str) -> Result<ServerConfig, Self::Err> {
        ServerConfig::from_url(s)
    }
}

/// Address for Manager server
#[derive(Debug, Clone)]
pub enum ManagerAddr {
    /// IP address
    SocketAddr(SocketAddr),
    /// Domain name address
    DomainName(String, u16),
    /// Unix socket path
    #[cfg(unix)]
    UnixSocketAddr(PathBuf),
}

/// Error for parsing `ManagerAddr`
#[derive(Debug)]
pub struct ManagerAddrError;

impl FromStr for ManagerAddr {
    type Err = ManagerAddrError;

    fn from_str(s: &str) -> Result<ManagerAddr, ManagerAddrError> {
        match s.find(':') {
            Some(pos) => {
                // Contains a ':' in address, must be IP:Port or Domain:Port
                match s.parse::<SocketAddr>() {
                    Ok(saddr) => Ok(ManagerAddr::SocketAddr(saddr)),
                    Err(..) => {
                        // Splits into Domain and Port
                        let (sdomain, sport) = s.split_at(pos);
                        let (sdomain, sport) = (sdomain.trim(), sport[1..].trim());

                        match sport.parse::<u16>() {
                            Ok(port) => Ok(ManagerAddr::DomainName(sdomain.to_owned(), port)),
                            Err(..) => Err(ManagerAddrError),
                        }
                    }
                }
            }
            #[cfg(unix)]
            None => {
                // Must be a unix socket path
                Ok(ManagerAddr::UnixSocketAddr(PathBuf::from(s)))
            }
            #[cfg(not(unix))]
            None => Err(ManagerAddrError),
        }
    }
}

impl Display for ManagerAddr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            ManagerAddr::SocketAddr(ref saddr) => fmt::Display::fmt(saddr, f),
            ManagerAddr::DomainName(ref dname, port) => write!(f, "{}:{}", dname, port),
            #[cfg(unix)]
            ManagerAddr::UnixSocketAddr(ref path) => fmt::Display::fmt(&path.display(), f),
        }
    }
}

impl From<SocketAddr> for ManagerAddr {
    fn from(addr: SocketAddr) -> ManagerAddr {
        ManagerAddr::SocketAddr(addr)
    }
}

impl<'a> From<(&'a str, u16)> for ManagerAddr {
    fn from((dname, port): (&'a str, u16)) -> ManagerAddr {
        ManagerAddr::DomainName(dname.to_owned(), port)
    }
}

impl From<(String, u16)> for ManagerAddr {
    fn from((dname, port): (String, u16)) -> ManagerAddr {
        ManagerAddr::DomainName(dname, port)
    }
}

#[cfg(unix)]
impl From<PathBuf> for ManagerAddr {
    fn from(p: PathBuf) -> ManagerAddr {
        ManagerAddr::UnixSocketAddr(p)
    }
}

cfg_if! {
    if #[cfg(feature = "local-dns")] {
        /// Parse `LocalDnsAddr` error
        #[derive(Debug)]
        pub struct LocalDnsAddrError;

        /// Address for Manager server
        #[derive(Debug, Clone)]
        pub enum LocalDnsAddr {
            /// IP address
            SocketAddr(SocketAddr),
            /// Unix socket path
            #[cfg(unix)]
            UnixSocketAddr(PathBuf),
        }

        impl FromStr for LocalDnsAddr {
            type Err = LocalDnsAddrError;

            fn from_str(s: &str) -> Result<LocalDnsAddr, LocalDnsAddrError> {
                match s.parse::<SocketAddr>() {
                    Ok(socket_addr) => Ok(LocalDnsAddr::SocketAddr(socket_addr)),
                    #[cfg(unix)]
                    Err(..) => Ok(LocalDnsAddr::UnixSocketAddr(PathBuf::from(s))),
                    #[cfg(not(unix))]
                    Err(..) => Err(LocalDnsAddrError),
                }
            }
        }

        impl Display for LocalDnsAddr {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                match *self {
                    LocalDnsAddr::SocketAddr(ref saddr) => fmt::Display::fmt(saddr, f),
                    #[cfg(unix)]
                    LocalDnsAddr::UnixSocketAddr(ref path) => fmt::Display::fmt(&path.display(), f),
                }
            }
        }

        impl From<SocketAddr> for LocalDnsAddr {
            fn from(addr: SocketAddr) -> LocalDnsAddr {
                LocalDnsAddr::SocketAddr(addr)
            }
        }

        #[cfg(unix)]
        impl From<PathBuf> for LocalDnsAddr {
            fn from(p: PathBuf) -> LocalDnsAddr {
                LocalDnsAddr::UnixSocketAddr(p)
            }
        }

        #[cfg(unix)]
        impl From<&str> for LocalDnsAddr {
            fn from(p: &str) -> LocalDnsAddr {
                LocalDnsAddr::UnixSocketAddr(PathBuf::from(p))
            }
        }
    }
}

/// Shadowsocks URL parsing Error
#[derive(Debug, Clone)]
pub enum UrlParseError {
    ParseError(url::ParseError),
    InvalidScheme,
    InvalidUserInfo,
    MissingHost,
    InvalidAuthInfo,
    InvalidServerAddr,
    InvalidQueryString,
}

impl From<url::ParseError> for UrlParseError {
    fn from(err: url::ParseError) -> UrlParseError {
        UrlParseError::ParseError(err)
    }
}

impl fmt::Display for UrlParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UrlParseError::ParseError(ref err) => fmt::Display::fmt(err, f),
            UrlParseError::InvalidScheme => write!(f, "URL must have \"ss://\" scheme"),
            UrlParseError::InvalidUserInfo => write!(f, "invalid user info"),
            UrlParseError::MissingHost => write!(f, "missing host"),
            UrlParseError::InvalidAuthInfo => write!(f, "invalid authentication info"),
            UrlParseError::InvalidServerAddr => write!(f, "invalid server address"),
            UrlParseError::InvalidQueryString => write!(f, "invalid query string"),
        }
    }
}

impl error::Error for UrlParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            UrlParseError::ParseError(ref err) => Some(err as &dyn error::Error),
            UrlParseError::InvalidScheme => None,
            UrlParseError::InvalidUserInfo => None,
            UrlParseError::MissingHost => None,
            UrlParseError::InvalidAuthInfo => None,
            UrlParseError::InvalidServerAddr => None,
            UrlParseError::InvalidQueryString => None,
        }
    }
}

/// Listening address
pub type ClientConfig = ServerAddr;

/// Server config type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigType {
    /// Config for socks5 local
    ///
    /// Requires `local` configuration
    Socks5Local,

    /// Config for socks4 local
    ///
    /// Requires `local` configuration
    #[cfg(feature = "local-socks4")]
    Socks4Local,

    /// Config for HTTP local
    ///
    /// Requires `local` configuration
    #[cfg(feature = "local-http")]
    HttpLocal,

    /// Config for HTTPS local
    ///
    /// Requires `local` configuration
    #[cfg(all(
        feature = "local-http",
        any(feature = "local-http-native-tls", feature = "local-http-rustls")
    ))]
    HttpsLocal,

    /// Config for tunnel local
    ///
    /// Requires `local` and `forward` configuration
    #[cfg(feature = "local-tunnel")]
    TunnelLocal,

    /// Config for redir local
    ///
    /// Requires `local` configuration
    #[cfg(feature = "local-redir")]
    RedirLocal,

    /// Config for dns relay local
    ///
    /// Requires `local` configuration
    #[cfg(feature = "local-dns")]
    DnsLocal,

    /// Config for server
    Server,

    /// Config for Manager server
    Manager,
}

impl ConfigType {
    /// Check if it is local server type
    pub fn is_local(self) -> bool {
        match self {
            ConfigType::Socks5Local => true,
            #[cfg(feature = "local-socks4")]
            ConfigType::Socks4Local => true,
            #[cfg(feature = "local-dns")]
            ConfigType::DnsLocal => true,
            #[cfg(feature = "local-tunnel")]
            ConfigType::TunnelLocal => true,
            #[cfg(feature = "local-http")]
            ConfigType::HttpLocal => true,
            #[cfg(all(
                feature = "local-http",
                any(feature = "local-http-native-tls", feature = "local-http-rustls")
            ))]
            ConfigType::HttpsLocal => true,
            #[cfg(feature = "local-redir")]
            ConfigType::RedirLocal => true,
            ConfigType::Server | ConfigType::Manager => false,
        }
    }

    /// Check if it is remote server type
    pub fn is_server(self) -> bool {
        match self {
            ConfigType::Socks5Local => false,
            #[cfg(feature = "local-socks4")]
            ConfigType::Socks4Local => false,
            #[cfg(feature = "local-dns")]
            ConfigType::DnsLocal => false,
            #[cfg(feature = "local-tunnel")]
            ConfigType::TunnelLocal => false,
            #[cfg(feature = "local-http")]
            ConfigType::HttpLocal => false,
            #[cfg(all(
                feature = "local-http",
                any(feature = "local-http-native-tls", feature = "local-http-rustls")
            ))]
            ConfigType::HttpsLocal => false,
            #[cfg(feature = "local-redir")]
            ConfigType::RedirLocal => false,
            ConfigType::Manager => false,
            ConfigType::Server => true,
        }
    }

    /// Check if it is manager server type
    pub fn is_manager(self) -> bool {
        matches!(self, ConfigType::Manager)
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
        ManagerServerHost::Ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
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

impl ManagerServerHost {
    /// Get resolved socket address for servers to bind
    pub async fn bind_addr(&self, ctx: &Context, port: u16) -> io::Result<SocketAddr> {
        match *self {
            ManagerServerHost::Domain(ref domain) => {
                let vaddrs = ctx.dns_resolve(domain, port).await?;
                Ok(vaddrs[0])
            }
            ManagerServerHost::Ip(ip) => Ok(SocketAddr::new(ip, port)),
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

    /// Get resolved socket address for servers to bind
    pub async fn bind_addr(&self, ctx: &Context, port: u16) -> io::Result<SocketAddr> {
        self.server_host.bind_addr(ctx, port).await
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
    /// Manager's configuration
    pub manager: Option<ManagerConfig>,
    /// Config is for Client or Server
    pub config_type: ConfigType,
    /// Timeout for UDP Associations, default is 5 minutes
    pub udp_timeout: Option<Duration>,
    /// Maximum number of UDP Associations, default is unconfigured
    pub udp_max_associations: Option<usize>,
    /// UDP relay's bind address, it uses `local_addr` by default
    ///
    /// Resolving Android's issue: https://github.com/shadowsocks/shadowsocks-android/issues/2571
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
    pub protect_path: Option<PathBuf>,
    /// Internal DNS's bind address
    #[cfg(feature = "local-dns")]
    pub dns_bind_addr: Option<ClientConfig>,
    /// Local DNS's address
    ///
    /// Sending DNS query directly to this address
    #[cfg(feature = "local-dns")]
    pub local_dns_addr: Option<LocalDnsAddr>,
    /// Remote DNS's address
    ///
    /// Sending DNS query through proxy to this address
    #[cfg(feature = "local-dns")]
    pub remote_dns_addr: Option<Address>,
    /// Uses IPv6 addresses first
    ///
    /// Set to `true` if you want to query IPv6 addresses before IPv4
    pub ipv6_first: bool,
    /// TLS cryptographic identity (X509), PKCS #12 format
    #[cfg(feature = "local-http-native-tls")]
    pub tls_identity_path: Option<PathBuf>,
    /// TLS cryptographic identity's password
    #[cfg(feature = "local-http-native-tls")]
    pub tls_identity_password: Option<String>,
    /// TLS cryptographic identity, certificate file path (PEM)
    #[cfg(feature = "local-http-rustls")]
    pub tls_identity_certificate_path: Option<PathBuf>,
    /// TLS cryptographic identity, private keys (PEM), RSA or PKCS #8
    #[cfg(feature = "local-http-rustls")]
    pub tls_identity_private_key_path: Option<PathBuf>,
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
            manager: None,
            config_type,
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
            protect_path: None,
            #[cfg(feature = "local-dns")]
            dns_bind_addr: None,
            #[cfg(feature = "local-dns")]
            local_dns_addr: None,
            #[cfg(feature = "local-dns")]
            remote_dns_addr: None,
            ipv6_first: false,
            #[cfg(feature = "local-http-native-tls")]
            tls_identity_path: None,
            #[cfg(feature = "local-http-native-tls")]
            tls_identity_password: None,
            #[cfg(feature = "local-http-rustls")]
            tls_identity_certificate_path: None,
            #[cfg(feature = "local-http-rustls")]
            tls_identity_private_key_path: None,
        }
    }

    fn load_from_ssconfig(config: SSConfig, config_type: ConfigType) -> Result<Config, Error> {
        let mut nconfig = Config::new(config_type);

        // Standard config
        // Client
        if let Some(la) = config.local_address {
            let port = match config.local_port {
                // Let system allocate port by default
                None => {
                    let err = Error::new(ErrorKind::MissingField, "missing `local_port`", None);
                    return Err(err);
                }
                Some(p) => {
                    if config_type.is_server() {
                        // Server can only bind to address, port should always be 0
                        0
                    } else {
                        p
                    }
                }
            };

            let local = match la.parse::<IpAddr>() {
                Ok(ip) => ServerAddr::from(SocketAddr::new(ip, port)),
                Err(..) => {
                    // treated as domain
                    ServerAddr::from((la, port))
                }
            };

            nconfig.local_addr = Some(local);
        }

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

                let plugin = match config.plugin {
                    None => None,
                    Some(p) => {
                        if p.is_empty() {
                            // SIP008 allows "plugin" to be an empty string
                            // Empty string implies "no plugin"
                            None
                        } else {
                            Some(PluginConfig {
                                plugin: p,
                                plugin_opts: config.plugin_opts,
                                plugin_args: config.plugin_args.unwrap_or_default(),
                            })
                        }
                    }
                };

                let timeout = config.timeout.map(Duration::from_secs);
                let nsvr = ServerConfig::new(addr, pwd, method, timeout, plugin);

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

                let plugin = match svr.plugin {
                    None => None,
                    Some(p) => {
                        if p.is_empty() {
                            // SIP008 allows "plugin" to be an empty string
                            // Empty string implies "no plugin"
                            None
                        } else {
                            Some(PluginConfig {
                                plugin: p,
                                plugin_opts: svr.plugin_opts,
                                plugin_args: svr.plugin_args.unwrap_or_default(),
                            })
                        }
                    }
                };

                let timeout = svr.timeout.or(config.timeout).map(Duration::from_secs);
                let mut nsvr = ServerConfig::new(addr, svr.password, method, timeout, plugin);

                nsvr.remarks = svr.remarks;
                nsvr.id = svr.id;

                nconfig.server.push(nsvr);
            }
        }

        // Set timeout globally
        if let Some(timeout) = config.timeout {
            let timeout = Duration::from_secs(timeout);
            // Set as a default timeout
            for svr in &mut nconfig.server {
                if svr.timeout.is_none() {
                    svr.timeout = Some(timeout);
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

    #[cfg(feature = "trust-dns")]
    /// Get `trust-dns`'s `ResolverConfig` by DNS configuration string
    pub(crate) fn get_dns_config(&self) -> Option<ResolverConfig> {
        self.dns.clone()
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
            if self.local_addr.is_none() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing `local_address` and `local_port` for client configuration",
                    None,
                );
                return Err(err);
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
        }

        // Plugin shouldn't be an empty string
        for server in &self.server {
            if let Some(plugin) = server.plugin() {
                if plugin.plugin.trim().is_empty() {
                    let err = Error::new(ErrorKind::Malformed, "`plugin` shouldn't be an empty string", None);
                    return Err(err);
                }
            }
        }

        #[cfg(feature = "local-dns")]
        if self.config_type == ConfigType::DnsLocal {
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

        #[cfg(all(
            feature = "local-http",
            any(feature = "local-http-native-tls", feature = "local-http-rustls")
        ))]
        if self.config_type == ConfigType::HttpsLocal {
            #[cfg(feature = "local-http-rustls")]
            if self.tls_identity_certificate_path.is_none() || self.tls_identity_private_key_path.is_none() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing `tls_identity_certificate_path` or `tls_identity_private_key_path` in configuration",
                    None,
                );
                return Err(err);
            }

            #[cfg(feature = "local-http-native-tls")]
            if self.tls_identity_path.is_none() || self.tls_identity_password.is_none() {
                let err = Error::new(
                    ErrorKind::MissingField,
                    "missing `tls_identity_path` or `tls_identity_password` in configuration",
                    None,
                );
                return Err(err);
            }
        }

        #[cfg(feature = "local-flow-stat")]
        if self.stat_path.is_none() {
            let err = Error::new(ErrorKind::MissingField, "missing `stat_path` in configuration", None);
            return Err(err);
        }

        #[cfg(feature = "local-tunnel")]
        if self.config_type == ConfigType::TunnelLocal {
            if self.forward.is_none() {
                let err = Error::new(ErrorKind::MissingField, "missing `forward` in configuration", None);
                return Err(err);
            }
        }

        Ok(())
    }

    /// Check if DNS Relay is enabled
    #[cfg(feature = "local-dns")]
    pub(crate) fn is_local_dns_relay(&self) -> bool {
        self.config_type == ConfigType::DnsLocal || self.dns_bind_addr.is_some()
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
            1 if self.server[0].id().is_none() && self.server[0].remarks.is_none() => {
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
                        remarks: svr.remarks.clone(),
                        id: svr.id.clone(),
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
