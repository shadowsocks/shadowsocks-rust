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
//!             "address": "127.0.0.1",
//!             "port": 1080,
//!             "password": "hellofuck",
//!             "method": "bf-cfb"
//!         },
//!         {
//!             "address": "127.0.0.1",
//!             "port": 1081,
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
    collections::HashSet,
    convert::From,
    default::Default,
    error,
    fmt::{self, Debug, Display, Formatter},
    fs::OpenOptions,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    option::Option,
    path::Path,
    str::FromStr,
    string::ToString,
    time::Duration,
};

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use bytes::Bytes;
use json5;
use log::error;
use serde::{Deserialize, Serialize};
use serde_urlencoded;
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};
use url::{self, Url};

use crate::{crypto::cipher::CipherType, plugin::PluginConfig};

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
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_opts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    servers: Option<Vec<SSServerExtConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    forbidden_ip: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_delay: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SSServerExtConfig {
    address: String,
    port: u16,
    password: String,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin_opts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_timeout: Option<u64>,
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
    /// Get address for server listener
    /// Panic if address is domain name
    pub fn listen_addr(&self) -> &SocketAddr {
        match *self {
            ServerAddr::SocketAddr(ref s) => s,
            _ => panic!("Cannot use domain name as server listen address"),
        }
    }

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

/// Configuration for a server
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Server address
    addr: ServerAddr,
    /// Encryption password (key)
    password: String,
    /// Encryption type (method)
    method: CipherType,
    /// Connection timeout
    timeout: Option<Duration>,
    /// Encryption key
    enc_key: Bytes,
    /// Plugin config
    plugin: Option<PluginConfig>,
    /// UDP timeout
    udp_timeout: Option<Duration>,
    /// Plugin address
    plugin_addr: Option<ServerAddr>,
}

impl ServerConfig {
    /// Creates a new ServerConfig
    pub fn new(
        addr: ServerAddr,
        pwd: String,
        method: CipherType,
        timeout: Option<Duration>,
        plugin: Option<PluginConfig>,
    ) -> ServerConfig {
        let enc_key = method.bytes_to_key(pwd.as_bytes());
        ServerConfig {
            addr,
            password: pwd,
            method,
            timeout,
            enc_key,
            plugin,
            udp_timeout: None,
            plugin_addr: None,
        }
    }

    /// Create a basic config
    pub fn basic(addr: SocketAddr, password: String, method: CipherType) -> ServerConfig {
        ServerConfig::new(ServerAddr::SocketAddr(addr), password, method, None, None)
    }

    /// Set encryption method
    pub fn set_method(&mut self, t: CipherType, pwd: String) {
        self.password = pwd;
        self.method = t;
        self.enc_key = t.bytes_to_key(self.password.as_bytes());
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

    /// Get password
    pub fn password(&self) -> &str {
        &self.password[..]
    }

    /// Get method
    pub fn method(&self) -> CipherType {
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

    /// Get UDP timeout
    pub fn udp_timeout(&self) -> &Option<Duration> {
        &self.udp_timeout
    }

    /// Set plugin address
    pub fn set_plugin_addr(&mut self, a: ServerAddr) {
        self.plugin_addr = Some(a);
    }

    /// Get plugin address
    pub fn plugin_addr(&self) -> &Option<ServerAddr> {
        &self.plugin_addr
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
            if let Some(ref opt) = c.plugin_opt {
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
                            plugin_opt: vsp.next().map(ToOwned::to_owned),
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
    fn description(&self) -> &str {
        match *self {
            UrlParseError::ParseError(ref err) => error::Error::description(err),
            UrlParseError::InvalidScheme => "URL must have \"ss://\" scheme",
            UrlParseError::InvalidUserInfo => "invalid user info",
            UrlParseError::MissingHost => "missing host",
            UrlParseError::InvalidAuthInfo => "invalid authentication info",
            UrlParseError::InvalidServerAddr => "invalid server address",
            UrlParseError::InvalidQueryString => "invalid query string",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
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
pub type ClientConfig = SocketAddr;

/// Server config type
#[derive(Clone, Copy, Debug)]
pub enum ConfigType {
    /// Config for local
    ///
    /// Requires `local` configuration
    Local,
    /// Config for server
    Server,
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
        match self {
            Mode::UdpOnly | Mode::TcpAndUdp => true,
            _ => false,
        }
    }

    pub fn enable_tcp(self) -> bool {
        match self {
            Mode::TcpOnly | Mode::TcpAndUdp => true,
            _ => false,
        }
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

/// Configuration
#[derive(Clone, Debug)]
pub struct Config {
    pub server: Vec<ServerConfig>,
    pub local: Option<ClientConfig>,
    pub forward: Option<SocketAddr>,
    pub forbidden_ip: HashSet<IpAddr>,
    pub dns: Option<String>,
    pub mode: Mode,
    pub no_delay: bool,
    pub manager_address: Option<ServerAddr>,
    pub config_type: ConfigType,
}

/// Configuration parsing error kind
#[derive(Copy, Clone, Debug)]
pub enum ErrorKind {
    MissingField,
    Malformed,
    Invalid,
    JsonParsingError,
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

impl Config {
    /// Creates an empty configuration
    pub fn new(config_type: ConfigType) -> Config {
        Config {
            server: Vec::new(),
            local: None,
            forward: None,
            forbidden_ip: HashSet::new(),
            dns: None,
            mode: Mode::TcpOnly,
            no_delay: false,
            manager_address: None,
            config_type,
        }
    }

    fn load_from_ssconfig(config: SSConfig, config_type: ConfigType) -> Result<Config, Error> {
        let check_local = match config_type {
            ConfigType::Local => true,
            ConfigType::Server => false,
        };

        if check_local && (config.local_address.is_none() || config.local_port.is_none()) {
            let err = Error::new(
                ErrorKind::Malformed,
                "`local_address` and `local_port` are required in client",
                None,
            );
            return Err(err);
        }

        let mut nconfig = Config::new(config_type);

        // Standard config
        // Client
        if let Some(la) = config.local_address {
            let port = config.local_port.unwrap();

            let local = match la.parse::<Ipv4Addr>() {
                Ok(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                Err(..) => match la.parse::<Ipv6Addr>() {
                    Ok(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                    Err(..) => {
                        let err = Error::new(
                            ErrorKind::Malformed,
                            "`local_address` must be an ipv4 or ipv6 address",
                            None,
                        );
                        return Err(err);
                    }
                },
            };

            nconfig.local = Some(local);
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

                let method = match m.parse::<CipherType>() {
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
                    Some(plugin) => Some(PluginConfig {
                        plugin,
                        plugin_opt: config.plugin_opts,
                    }),
                };

                let timeout = config.timeout.map(Duration::from_secs);
                let udp_timeout = config.udp_timeout.map(Duration::from_secs);

                let mut nsvr = ServerConfig::new(addr, pwd, method, timeout, plugin);

                nsvr.udp_timeout = udp_timeout;

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
                let addr = match svr.address.parse::<Ipv4Addr>() {
                    Ok(v4) => ServerAddr::SocketAddr(SocketAddr::V4(SocketAddrV4::new(v4, svr.port))),
                    Err(..) => match svr.address.parse::<Ipv6Addr>() {
                        Ok(v6) => ServerAddr::SocketAddr(SocketAddr::V6(SocketAddrV6::new(v6, svr.port, 0, 0))),
                        Err(..) => ServerAddr::DomainName(svr.address, svr.port),
                    },
                };

                let method = match svr.method.parse::<CipherType>() {
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
                    Some(p) => Some(PluginConfig {
                        plugin: p,
                        plugin_opt: svr.plugin_opts,
                    }),
                };

                let timeout = svr.timeout.map(Duration::from_secs);
                let udp_timeout = config.udp_timeout.map(Duration::from_secs);

                let mut nsvr = ServerConfig::new(addr, svr.password, method, timeout, plugin);

                nsvr.udp_timeout = udp_timeout;

                nconfig.server.push(nsvr);
            }
        }

        // Forbidden IPs
        if let Some(forbidden_ip) = config.forbidden_ip {
            for fi in forbidden_ip {
                match fi.parse::<IpAddr>() {
                    Ok(i) => {
                        nconfig.forbidden_ip.insert(i);
                    }
                    Err(err) => {
                        error!("Invalid forbidden_ip \"{}\", err: {}", fi, err);
                    }
                }
            }
        }

        // DNS
        nconfig.dns = config.dns;

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

        Ok(nconfig)
    }

    pub fn load_from_str(s: &str, config_type: ConfigType) -> Result<Config, Error> {
        let c = json5::from_str::<SSConfig>(s)?;
        Config::load_from_ssconfig(c, config_type)
    }

    pub fn load_from_file(filename: &str, config_type: ConfigType) -> Result<Config, Error> {
        let mut reader = OpenOptions::new().read(true).open(&Path::new(filename))?;
        let mut content = String::new();
        reader.read_to_string(&mut content)?;
        Config::load_from_str(&content[..], config_type)
    }

    #[cfg(feature = "trust-dns")]
    pub fn get_dns_config(&self) -> Option<ResolverConfig> {
        self.dns.as_ref().and_then(|ds| {
            match &ds[..] {
                "google" => Some(ResolverConfig::google()),

                "cloudflare" => Some(ResolverConfig::cloudflare()),
                "cloudflare_tls" => Some(ResolverConfig::cloudflare_tls()),
                "cloudflare_https" => Some(ResolverConfig::cloudflare_https()),

                "quad9" => Some(ResolverConfig::quad9()),
                "quad9_tls" => Some(ResolverConfig::quad9_tls()),

                _ => {
                    // Set ips directly
                    match ds.parse::<IpAddr>() {
                        Ok(ip) => Some(ResolverConfig::from_parts(
                            None,
                            vec![],
                            NameServerConfigGroup::from_ips_clear(&[ip], 53),
                        )),
                        Err(..) => {
                            error!(
                                "Failed to parse DNS \"{}\" in config to IpAddr, fallback to system config",
                                ds
                            );
                            None
                        }
                    }
                }
            }
        })
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
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Convert to json

        let mut jconf = SSConfig::default();

        if let Some(ref client) = self.local {
            jconf.local_address = Some(client.ip().to_string());
            jconf.local_port = Some(client.port());
        }

        // Servers
        // For 1 servers, uses standard configure format
        if self.server.len() == 1 {
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
            jconf.plugin_opts = svr.plugin().and_then(|p| p.plugin_opt.clone());
            jconf.timeout = svr.timeout().map(|t| t.as_secs());
            jconf.udp_timeout = svr.udp_timeout().map(|t| t.as_secs());
        } else if self.server.len() > 1 {
            let mut vsvr = Vec::new();

            for svr in &self.server {
                vsvr.push(SSServerExtConfig {
                    address: match *svr.addr() {
                        ServerAddr::SocketAddr(ref sa) => sa.ip().to_string(),
                        ServerAddr::DomainName(ref dm, ..) => dm.to_string(),
                    },
                    port: match *svr.addr() {
                        ServerAddr::SocketAddr(ref sa) => sa.port(),
                        ServerAddr::DomainName(.., port) => port,
                    },
                    password: svr.password().to_string(),
                    method: svr.method().to_string(),
                    plugin: svr.plugin().map(|p| p.plugin.to_string()),
                    plugin_opts: svr.plugin().and_then(|p| p.plugin_opt.clone()),
                    timeout: svr.timeout().map(|t| t.as_secs()),
                    udp_timeout: svr.udp_timeout().map(|t| t.as_secs()),
                });
            }
        }

        jconf.mode = Some(self.mode.to_string());

        if self.no_delay {
            jconf.no_delay = Some(self.no_delay);
        }

        if !self.forbidden_ip.is_empty() {
            let mut vfi = Vec::new();
            for fi in &self.forbidden_ip {
                vfi.push(fi.to_string());
            }
            jconf.forbidden_ip = Some(vfi);
        }

        if let Some(ref dns) = self.dns {
            jconf.dns = Some(dns.to_string());
        }

        write!(f, "{}", json5::to_string(&jconf).unwrap())
    }
}
