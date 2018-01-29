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
//! 

use std::collections::HashSet;
use std::convert::From;
use std::default::Default;
use std::error;
use std::fmt::{self, Debug, Display, Formatter};
use std::fs::OpenOptions;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::net::IpAddr;
use std::option::Option;
use std::path::Path;
use std::str::FromStr;
use std::string::ToString;
use std::time::Duration;

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use bytes::Bytes;
use serde_json::{self, Map, Value};
use serde_urlencoded;
use url::{self, Url};

use crypto::cipher::CipherType;
use plugin::PluginConfig;

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

    fn to_json_object_inner(&self, obj: &mut Map<String, Value>, addr_key: &str, port_key: &str) {
        match *self {
            ServerAddr::SocketAddr(SocketAddr::V4(ref v4)) => {
                obj.insert(addr_key.to_owned(), Value::String(v4.ip().to_string()));
                obj.insert(port_key.to_owned(), Value::Number(From::from(v4.port())));
            }
            ServerAddr::SocketAddr(SocketAddr::V6(ref v6)) => {
                obj.insert(addr_key.to_owned(), Value::String(v6.ip().to_string()));
                obj.insert(port_key.to_owned(), Value::Number(From::from(v6.port())));
            }
            ServerAddr::DomainName(ref domain, port) => {
                obj.insert(addr_key.to_owned(), Value::String(domain.to_owned()));
                obj.insert(port_key.to_owned(), Value::Number(From::from(port)));
            }
        }
    }

    fn to_json_object(&self, obj: &mut Map<String, Value>) {
        self.to_json_object_inner(obj, "address", "port")
    }

    fn to_json_object_old(&self, obj: &mut Map<String, Value>) {
        self.to_json_object_inner(obj, "server", "server_port")
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
        trace!("Initialize config with pwd: {:?}, key: {:?}", pwd, enc_key);
        ServerConfig {
            addr: addr,
            password: pwd,
            method: method,
            timeout: timeout,
            enc_key: enc_key,
            plugin: plugin,
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
    pub fn timeout(&self) -> &Option<Duration> {
        &self.timeout
    }

    /// Get plugin
    pub fn plugin(&self) -> Option<&PluginConfig> {
        self.plugin.as_ref()
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

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            UrlParseError::ParseError(ref err) => Some(err as &error::Error),
            UrlParseError::InvalidScheme => None,
            UrlParseError::InvalidUserInfo => None,
            UrlParseError::MissingHost => None,
            UrlParseError::InvalidAuthInfo => None,
            UrlParseError::InvalidServerAddr => None,
            UrlParseError::InvalidQueryString => None,
        }
    }
}

impl ServerConfig {
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();

        self.addr.to_json_object(&mut obj);

        obj.insert("password".to_owned(), Value::String(self.password.clone()));
        obj.insert("method".to_owned(), Value::String(self.method.to_string()));
        if let Some(t) = self.timeout {
            obj.insert("timeout".to_owned(), Value::Number(From::from(t.as_secs())));
        }

        if let Some(ref p) = self.plugin {
            obj.insert("plugin".to_owned(), Value::String(p.plugin.clone()));
            if let Some(ref opt) = p.plugin_opt {
                obj.insert("plugin_opts".to_owned(), Value::String(opt.clone()));
            }
        }

        Value::Object(obj)
    }
}

/// Listening address
pub type ClientConfig = SocketAddr;

/// Server config type
#[derive(Clone, Copy)]
pub enum ConfigType {
    /// Config for local
    ///
    /// Requires `local` configuration
    Local,
    /// Config for server
    Server,
}

/// Configuration
#[derive(Clone, Debug)]
pub struct Config {
    pub server: Vec<ServerConfig>,
    pub local: Option<ClientConfig>,
    pub enable_udp: bool,
    pub forbidden_ip: HashSet<IpAddr>,
}

impl Default for Config {
    fn default() -> Config {
        Config::new()
    }
}

/// Configuration parsing error kind
#[derive(Copy, Clone)]
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
        Error {
            kind: kind,
            desc: desc,
            detail: detail,
        }
    }
}

macro_rules! impl_from {
    ($error:ty,$kind:expr,$desc:expr) => (
        impl From<$error> for Error {
            fn from(err:$error) -> Self {
                Error::new($kind,$desc,Some(format!("{:?}",err)))
            }
        }
    )
}

impl_from!(
    ::std::io::Error,
    ErrorKind::IoError,
    "error while reading file"
);
impl_from!(
    serde_json::Error,
    ErrorKind::JsonParsingError,
    "Json parse error"
);

macro_rules! except {
    ($expr:expr,$kind:expr,$desc:expr) => (except!($expr,$kind,$desc,None));
    ($expr:expr,$kind:expr,$desc:expr,$detail:expr) => (
        match $expr {
            ::std::option::Option::Some(val) => val,
            ::std::option::Option::None => {
                return ::std::result::Result::Err(
                    $crate::config::Error::new($kind,$desc,$detail)
                )
            }
        }
    )
}
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
    pub fn new() -> Config {
        Config {
            server: Vec::new(),
            local: None,
            enable_udp: false,
            forbidden_ip: HashSet::new(),
        }
    }

    fn parse_server(server: &Map<String, Value>) -> Result<ServerConfig, Error> {
        let method = server
            .get("method")
            .ok_or_else(|| Error::new(ErrorKind::MissingField, "need to specify a method", None))
            .and_then(|method_o| {
                method_o
                    .as_str()
                    .ok_or_else(|| Error::new(ErrorKind::Malformed, "`method` should be a string", None))
            })
            .and_then(|method_str| {
                method_str.parse::<CipherType>().map_err(|_| {
                    Error::new(
                        ErrorKind::Invalid,
                        "not supported method",
                        Some(format!("`{}` is not a supported method", method_str)),
                    )
                })
            })?;

        let port = server
            .get("port")
            .or_else(|| server.get("server_port"))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::MissingField,
                    "need to specify a server port",
                    None,
                )
            })
            .and_then(|port_o| {
                port_o
                    .as_u64()
                    .map(|u| u as u16)
                    .ok_or_else(|| Error::new(ErrorKind::Malformed, "`port` should be an integer", None))
            })?;

        let addr = server
            .get("address")
            .or_else(|| server.get("server"))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::MissingField,
                    "need to specify a server address",
                    None,
                )
            })
            .and_then(|addr_o| {
                addr_o
                    .as_str()
                    .ok_or_else(|| Error::new(ErrorKind::Malformed, "`address` should be a string", None))
            })
            .and_then(|addr_str| {
                addr_str
                    .parse::<Ipv4Addr>()
                    .map(|v4| ServerAddr::SocketAddr(SocketAddr::V4(SocketAddrV4::new(v4, port))))
                    .or_else(|_| {
                        addr_str
                            .parse::<Ipv6Addr>()
                            .map(|v6| ServerAddr::SocketAddr(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0))))
                    })
                    .or_else(|_| Ok(ServerAddr::DomainName(addr_str.to_string(), port)))
            })?;

        let password = server
            .get("password")
            .ok_or_else(|| Error::new(ErrorKind::MissingField, "need to specify a password", None))
            .and_then(|pwd_o| {
                pwd_o
                    .as_str()
                    .ok_or_else(|| Error::new(ErrorKind::Malformed, "`password` should be a string", None))
                    .map(|s| s.to_string())
            })?;

        let timeout = match server.get("timeout") {
            Some(t) => {
                let val = t.as_u64().ok_or(Error::new(
                    ErrorKind::Malformed,
                    "`timeout` should be an integer",
                    None,
                ))?;
                Some(Duration::from_secs(val))
            }
            None => None,
        };

        let plugin = match server.get("plugin") {
            Some(p) => {
                let plugin = p.as_str()
                    .ok_or_else(|| Error::new(ErrorKind::Malformed, "`plugin` should be a string", None))?;

                let opt = match server.get("plugin_opts") {
                    None => None,
                    Some(o) => {
                        let o = o.as_str().ok_or_else(|| {
                            Error::new(
                                ErrorKind::Malformed,
                                "`plugin_opts` should be a string",
                                None,
                            )
                        })?;
                        Some(o.to_owned())
                    }
                };

                Some(PluginConfig {
                    plugin: plugin.to_owned(),
                    plugin_opt: opt,
                })
            }
            None => None,
        };

        Ok(ServerConfig::new(addr, password, method, timeout, plugin))
    }

    fn parse_json_object(o: &Map<String, Value>, require_local_info: bool) -> Result<Config, Error> {
        let mut config = Config::new();

        if o.contains_key("servers") {
            let server_list = o.get("servers").unwrap().as_array().ok_or(Error::new(
                ErrorKind::Malformed,
                "`servers` should be a list",
                None,
            ))?;

            for server in server_list.iter() {
                if let Some(server) = server.as_object() {
                    let cfg = Config::parse_server(server)?;
                    config.server.push(cfg);
                }
            }
        } else if o.contains_key("server") && o.contains_key("server_port") && o.contains_key("password")
            && o.contains_key("method")
        {
            // Traditional configuration file
            let single_server = Config::parse_server(o)?;
            config.server = vec![single_server];
        }

        if require_local_info {
            let has_local_address = o.contains_key("local_address");
            let has_local_port = o.contains_key("local_port");

            if has_local_address && has_local_port {
                config.local = match o.get("local_address") {
                    Some(local_addr) => {
                        let addr_str = local_addr.as_str().ok_or(Error::new(
                            ErrorKind::Malformed,
                            "`local_address` should be a string",
                            None,
                        ))?;

                        let port = o.get("local_port").unwrap().as_u64().ok_or(Error::new(
                            ErrorKind::Malformed,
                            "`local_port` should be an integer",
                            None,
                        ))? as u16;

                        match addr_str.parse::<Ipv4Addr>() {
                            Ok(ip) => Some(SocketAddr::V4(SocketAddrV4::new(ip, port))),
                            Err(..) => match addr_str.parse::<Ipv6Addr>() {
                                Ok(ip) => Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
                                Err(..) => {
                                    return Err(Error::new(
                                        ErrorKind::Malformed,
                                        "`local_address` is not a valid IP \
                                         address",
                                        None,
                                    ))
                                }
                            },
                        }
                    }
                    None => None,
                };
            } else if has_local_address ^ has_local_port {
                panic!("You have to provide `local_address` and `local_port` together");
            }
        }

        if let Some(forbidden_ip_conf) = o.get("forbidden_ip") {
            let forbidden_ip_arr = forbidden_ip_conf.as_array().ok_or(Error::new(
                ErrorKind::Malformed,
                "`forbidden_ip` should be a list",
                None,
            ))?;
            config
                .forbidden_ip
                .extend(forbidden_ip_arr.into_iter().filter_map(|x| {
                    let x = match x.as_str() {
                        Some(x) => x,
                        None => {
                            error!(
                                "Forbidden IP should be a string, but found {:?}, skipping",
                                x
                            );
                            return None;
                        }
                    };

                    match x.parse::<IpAddr>() {
                        Ok(sock) => Some(sock),
                        Err(err) => {
                            error!("Invalid forbidden IP {}, {:?}, skipping", x, err);
                            None
                        }
                    }
                }));
        }

        if let Some(udp_enable) = o.get("enable_udp") {
            match udp_enable.as_bool() {
                None => {
                    let err = Error::new(ErrorKind::Malformed, "`enable_udp` should be boolean", None);
                    return Err(err);
                }
                Some(enable_udp) => config.enable_udp = enable_udp,
            }
        }

        Ok(config)
    }

    pub fn load_from_str(s: &str, config_type: ConfigType) -> Result<Config, Error> {
        let object = serde_json::from_str::<Value>(s)?;
        let json_object = except!(
            object.as_object(),
            ErrorKind::JsonParsingError,
            "root is not a JsonObject"
        );
        Config::parse_json_object(
            json_object,
            match config_type {
                ConfigType::Local => true,
                ConfigType::Server => false,
            },
        )
    }

    pub fn load_from_file(filename: &str, config_type: ConfigType) -> Result<Config, Error> {
        let reader = &mut OpenOptions::new().read(true).open(&Path::new(filename))?;
        let object = serde_json::from_reader::<_, Value>(reader)?;
        let json_object = except!(
            object.as_object(),
            ErrorKind::JsonParsingError,
            "root is not a JsonObject"
        );
        Config::parse_json_object(
            json_object,
            match config_type {
                ConfigType::Local => true,
                ConfigType::Server => false,
            },
        )
    }
}

impl Config {
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        if self.server.len() == 1 {
            // Official format

            let server = &self.server[0];
            server.addr.to_json_object_old(&mut obj);

            obj.insert(
                "password".to_owned(),
                Value::String(server.password.clone()),
            );
            obj.insert(
                "method".to_owned(),
                Value::String(server.method.to_string()),
            );
            if let Some(t) = server.timeout {
                obj.insert("timeout".to_owned(), Value::Number(From::from(t.as_secs())));
            }

            if let Some(ref p) = server.plugin {
                obj.insert("plugin".to_owned(), Value::String(p.plugin.clone()));
                if let Some(ref opt) = p.plugin_opt {
                    obj.insert("plugin_opts".to_owned(), Value::String(opt.clone()));
                }
            }
        } else {
            let arr: Vec<Value> = self.server.iter().map(|s| s.to_json()).collect();
            obj.insert("servers".to_owned(), Value::Array(arr));
        }

        if let Some(ref l) = self.local {
            let ip_str = match *l {
                SocketAddr::V4(ref v4) => v4.ip().to_string(),
                SocketAddr::V6(ref v6) => v6.ip().to_string(),
            };

            obj.insert("local_address".to_owned(), Value::String(ip_str));
            obj.insert(
                "local_port".to_owned(),
                Value::Number(From::from(l.port() as u64)),
            );
        }

        obj.insert("enable_udp".to_owned(), Value::Bool(self.enable_udp));

        Value::Object(obj)
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_json())
    }
}
