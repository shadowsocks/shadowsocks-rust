//! Configuration

#[cfg(unix)]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    error,
    fmt::{self, Debug, Display},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use base64::Engine as _;
use byte_string::ByteStr;
use bytes::Bytes;
use cfg_if::cfg_if;
use log::error;
use thiserror::Error;
use url::{self, Url};

use crate::{
    crypto::{v1::openssl_bytes_to_key, CipherKind},
    plugin::PluginConfig,
    relay::socks5::Address,
};

const USER_KEY_BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

const AEAD2022_PASSWORD_BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

const URL_PASSWORD_BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Shadowsocks server type
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServerType {
    /// Running as a local service
    Local,

    /// Running as a shadowsocks server
    Server,
}

impl ServerType {
    /// Check if it is `Local`
    pub fn is_local(self) -> bool {
        self == ServerType::Local
    }

    /// Check if it is `Server`
    pub fn is_server(self) -> bool {
        self == ServerType::Server
    }
}

/// Server mode
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    TcpOnly = 0x01,
    TcpAndUdp = 0x03,
    UdpOnly = 0x02,
}

impl Mode {
    /// Check if UDP is enabled
    pub fn enable_udp(self) -> bool {
        matches!(self, Mode::UdpOnly | Mode::TcpAndUdp)
    }

    /// Check if TCP is enabled
    pub fn enable_tcp(self) -> bool {
        matches!(self, Mode::TcpOnly | Mode::TcpAndUdp)
    }

    /// Merge with another Mode
    pub fn merge(&self, mode: Mode) -> Mode {
        let me = *self as u8;
        let fm = mode as u8;
        match me | fm {
            0x01 => Mode::TcpOnly,
            0x02 => Mode::UdpOnly,
            0x03 => Mode::TcpAndUdp,
            _ => unreachable!(),
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

/// Server's weight
///
/// Commonly for using in balancer
#[derive(Debug, Clone)]
pub struct ServerWeight {
    tcp_weight: f32,
    udp_weight: f32,
}

impl Default for ServerWeight {
    fn default() -> Self {
        ServerWeight::new()
    }
}

impl ServerWeight {
    /// Creates a default weight for server, which will have 1.0 for both TCP and UDP
    pub fn new() -> ServerWeight {
        ServerWeight {
            tcp_weight: 1.0,
            udp_weight: 1.0,
        }
    }

    /// Weight for TCP balancer
    pub fn tcp_weight(&self) -> f32 {
        self.tcp_weight
    }

    /// Set weight for TCP balancer in `[0, 1]`
    pub fn set_tcp_weight(&mut self, weight: f32) {
        assert!((0.0..=1.0).contains(&weight));
        self.tcp_weight = weight;
    }

    /// Weight for UDP balancer
    pub fn udp_weight(&self) -> f32 {
        self.udp_weight
    }

    /// Set weight for UDP balancer in `[0, 1]`
    pub fn set_udp_weight(&mut self, weight: f32) {
        assert!((0.0..=1.0).contains(&weight));
        self.udp_weight = weight;
    }
}

/// Server's user
#[derive(Clone)]
pub struct ServerUser {
    name: String,
    key: Bytes,
    identity_hash: Bytes,
}

impl Debug for ServerUser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerUser")
            .field("name", &self.name)
            .field("key", &USER_KEY_BASE64_ENGINE.encode(&self.key))
            .field("identity_hash", &ByteStr::new(&self.identity_hash))
            .finish()
    }
}

impl ServerUser {
    /// Create a user
    pub fn new<N, K>(name: N, key: K) -> ServerUser
    where
        N: Into<String>,
        K: Into<Bytes>,
    {
        let name = name.into();
        let key = key.into();

        let hash = blake3::hash(&key);
        let identity_hash = Bytes::from(hash.as_bytes()[0..16].to_owned());

        ServerUser {
            name,
            key,
            identity_hash,
        }
    }

    /// Create a user from encoded key
    pub fn with_encoded_key<N>(name: N, key: &str) -> Result<ServerUser, ServerUserError>
    where
        N: Into<String>,
    {
        let key = USER_KEY_BASE64_ENGINE.decode(key)?;
        Ok(ServerUser::new(name, key))
    }

    /// Name of the user
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Encryption key of user
    pub fn key(&self) -> &[u8] {
        self.key.as_ref()
    }

    /// Get Base64 encoded key of user
    pub fn encoded_key(&self) -> String {
        USER_KEY_BASE64_ENGINE.encode(&self.key)
    }

    /// User's identity hash
    ///
    /// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
    pub fn identity_hash(&self) -> &[u8] {
        self.identity_hash.as_ref()
    }

    /// User's identity hash
    ///
    /// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
    pub fn clone_identity_hash(&self) -> Bytes {
        self.identity_hash.clone()
    }
}

/// ServerUser related errors
#[derive(Debug, Clone, Error)]
pub enum ServerUserError {
    /// Invalid User key encoding
    #[error("{0}")]
    InvalidKeyEncoding(#[from] base64::DecodeError),
}

/// Server multi-users manager
#[derive(Clone, Debug)]
pub struct ServerUserManager {
    users: HashMap<Bytes, Arc<ServerUser>>,
}

impl ServerUserManager {
    /// Create a new manager
    pub fn new() -> ServerUserManager {
        ServerUserManager { users: HashMap::new() }
    }

    /// Add a new user
    pub fn add_user(&mut self, user: ServerUser) {
        self.users.insert(user.clone_identity_hash(), Arc::new(user));
    }

    /// Get user by hash key
    pub fn get_user_by_hash(&self, user_hash: &[u8]) -> Option<&ServerUser> {
        self.users.get(user_hash).map(AsRef::as_ref)
    }

    /// Get user by hash key cloned
    pub fn clone_user_by_hash(&self, user_hash: &[u8]) -> Option<Arc<ServerUser>> {
        self.users.get(user_hash).cloned()
    }

    /// Number of users
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Iterate users
    pub fn users_iter(&self) -> impl Iterator<Item = &ServerUser> {
        self.users.values().map(|v| v.as_ref())
    }
}

impl Default for ServerUserManager {
    fn default() -> ServerUserManager {
        ServerUserManager::new()
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
    /// Encryption key
    enc_key: Box<[u8]>,
    /// Handshake timeout (connect)
    timeout: Option<Duration>,

    /// Extensible Identity Headers (AEAD-2022)
    ///
    /// For client, assemble EIH headers
    identity_keys: Arc<Vec<Bytes>>,

    /// Extensible Identity Headers (AEAD-2022)
    ///
    /// For server, support multi-users with EIH
    user_manager: Option<Arc<ServerUserManager>>,

    /// Plugin config
    plugin: Option<PluginConfig>,
    /// Plugin address
    plugin_addr: Option<ServerAddr>,

    /// Remark (Profile Name), normally used as an identifier of this erver
    remarks: Option<String>,
    /// ID (SIP008) is a random generated UUID
    id: Option<String>,

    /// Mode
    mode: Mode,

    /// Weight
    weight: ServerWeight,
}

#[cfg(feature = "aead-cipher-2022")]
#[inline]
fn make_derived_key(method: CipherKind, password: &str, enc_key: &mut [u8]) {
    if method.is_aead_2022() {
        // AEAD 2022 password is a base64 form of enc_key
        match AEAD2022_PASSWORD_BASE64_ENGINE.decode(password) {
            Ok(v) => {
                if v.len() != enc_key.len() {
                    panic!(
                        "{} is expecting a {} bytes key, but password: {} ({} bytes after decode)",
                        method,
                        enc_key.len(),
                        password,
                        v.len()
                    );
                }
                enc_key.copy_from_slice(&v);
            }
            Err(err) => {
                panic!("{method} password {password} is not base64 encoded, error: {err}");
            }
        }
    } else {
        openssl_bytes_to_key(password.as_bytes(), enc_key);
    }
}

#[cfg(not(feature = "aead-cipher-2022"))]
#[inline]
fn make_derived_key(_method: CipherKind, password: &str, enc_key: &mut [u8]) {
    openssl_bytes_to_key(password.as_bytes(), enc_key);
}

/// Check if method supports Extended Identity Header
///
/// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
#[cfg(feature = "aead-cipher-2022")]
#[inline]
pub fn method_support_eih(method: CipherKind) -> bool {
    matches!(
        method,
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
    )
}

fn password_to_keys<P>(method: CipherKind, password: P) -> (String, Box<[u8]>, Vec<Bytes>)
where
    P: Into<String>,
{
    let password = password.into();

    #[cfg(feature = "aead-cipher-2022")]
    if method_support_eih(method) {
        // Extensible Identity Headers
        // iPSK1:iPSK2:iPSK3:...:uPSK

        let mut identity_keys = Vec::new();

        let mut split_iter = password.rsplit(':');

        let upsk = split_iter.next().expect("uPSK");

        let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
        make_derived_key(method, upsk, &mut enc_key);

        for ipsk in split_iter {
            match USER_KEY_BASE64_ENGINE.decode(ipsk) {
                Ok(v) => {
                    identity_keys.push(Bytes::from(v));
                }
                Err(err) => {
                    panic!("iPSK {ipsk} is not base64 encoded, error: {err}");
                }
            }
        }

        identity_keys.reverse();

        return (upsk.to_owned(), enc_key, identity_keys);
    }

    let mut enc_key = vec![0u8; method.key_len()].into_boxed_slice();
    make_derived_key(method, &password, &mut enc_key);

    (password, enc_key, Vec::new())
}

impl ServerConfig {
    /// Create a new `ServerConfig`
    pub fn new<A, P>(addr: A, password: P, method: CipherKind) -> ServerConfig
    where
        A: Into<ServerAddr>,
        P: Into<String>,
    {
        let (password, enc_key, identity_keys) = password_to_keys(method, password);

        ServerConfig {
            addr: addr.into(),
            password,
            method,
            enc_key,
            identity_keys: Arc::new(identity_keys),
            user_manager: None,
            timeout: None,
            plugin: None,
            plugin_addr: None,
            remarks: None,
            id: None,
            mode: Mode::TcpAndUdp, // Server serves TCP & UDP by default
            weight: ServerWeight::new(),
        }
    }

    /// Set encryption method
    pub fn set_method<P>(&mut self, method: CipherKind, password: P)
    where
        P: Into<String>,
    {
        self.method = method;

        let (password, enc_key, identity_keys) = password_to_keys(method, password);

        self.password = password;
        self.enc_key = enc_key;
        self.identity_keys = Arc::new(identity_keys);
    }

    /// Set plugin
    pub fn set_plugin(&mut self, p: PluginConfig) {
        self.plugin = Some(p);
    }

    /// Set server addr
    pub fn set_addr<A>(&mut self, a: A)
    where
        A: Into<ServerAddr>,
    {
        self.addr = a.into();
    }

    /// Get server address
    pub fn addr(&self) -> &ServerAddr {
        &self.addr
    }

    /// Get encryption key
    pub fn key(&self) -> &[u8] {
        self.enc_key.as_ref()
    }

    /// Get password
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    /// Get identity keys (Client)
    pub fn identity_keys(&self) -> &[Bytes] {
        &self.identity_keys
    }

    /// Clone identity keys (Client)
    pub fn clone_identity_keys(&self) -> Arc<Vec<Bytes>> {
        self.identity_keys.clone()
    }

    /// Set user manager, enable Server's multi-user support with EIH
    pub fn set_user_manager(&mut self, user_manager: ServerUserManager) {
        self.user_manager = Some(Arc::new(user_manager));
    }

    /// Get user manager (Server)
    pub fn user_manager(&self) -> Option<&ServerUserManager> {
        self.user_manager.as_deref()
    }

    /// Clone user manager (Server)
    pub fn clone_user_manager(&self) -> Option<Arc<ServerUserManager>> {
        self.user_manager.clone()
    }

    /// Get method
    pub fn method(&self) -> CipherKind {
        self.method
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

    /// Set timeout
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// Timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Get server's remark
    pub fn remarks(&self) -> Option<&str> {
        self.remarks.as_ref().map(AsRef::as_ref)
    }

    /// Set server's remark
    pub fn set_remarks<S>(&mut self, remarks: S)
    where
        S: Into<String>,
    {
        self.remarks = Some(remarks.into());
    }

    /// Get server's ID (SIP008)
    pub fn id(&self) -> Option<&str> {
        self.id.as_ref().map(AsRef::as_ref)
    }

    /// Set server's ID (SIP008)
    pub fn set_id<S>(&mut self, id: S)
    where
        S: Into<String>,
    {
        self.id = Some(id.into())
    }

    /// Get server's `Mode`
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Set server's `Mode`
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Get server's balancer weight
    pub fn weight(&self) -> &ServerWeight {
        &self.weight
    }

    /// Set server's balancer weight
    pub fn set_weight(&mut self, weight: ServerWeight) {
        self.weight = weight;
    }

    /// Get URL for QRCode
    /// ```plain
    /// ss:// + base64(method:password@host:port)
    /// ```
    pub fn to_qrcode_url(&self) -> String {
        let param = format!("{}:{}@{}", self.method(), self.password(), self.addr());
        format!("ss://{}", URL_PASSWORD_BASE64_ENGINE.encode(param))
    }

    /// Get [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    pub fn to_url(&self) -> String {
        cfg_if! {
            if #[cfg(feature = "aead-cipher-2022")] {
                let user_info = if !self.method().is_aead_2022() {
                    let user_info = format!("{}:{}", self.method(), self.password());
                    URL_PASSWORD_BASE64_ENGINE.encode(&user_info)
                } else {
                    format!("{}:{}", self.method(), percent_encoding::utf8_percent_encode(self.password(), percent_encoding::NON_ALPHANUMERIC))
                };
            } else {
                let mut user_info = format!("{}:{}", self.method(), self.password());
                user_info = URL_PASSWORD_BASE64_ENGINE.encode(&user_info)
            }
        }

        let mut url = format!("ss://{}@{}", user_info, self.addr());
        if let Some(c) = self.plugin() {
            let mut plugin = c.plugin.clone();
            if let Some(ref opt) = c.plugin_opts {
                plugin += ";";
                plugin += opt;
            }

            url += "/?plugin=";
            for c in percent_encoding::utf8_percent_encode(&plugin, percent_encoding::NON_ALPHANUMERIC) {
                url.push_str(c);
            }
        }

        if let Some(remark) = self.remarks() {
            url += "#";
            for c in percent_encoding::utf8_percent_encode(remark, percent_encoding::NON_ALPHANUMERIC) {
                url.push_str(c);
            }
        }

        url
    }

    /// Parse from [SIP002](https://github.com/shadowsocks/shadowsocks-org/issues/27) URL
    ///
    /// Extended formats:
    ///
    /// 1. QRCode URL supported by shadowsocks-android, https://github.com/shadowsocks/shadowsocks-android/issues/51
    /// 2. Plain userinfo:password format supported by go2-shadowsocks2
    pub fn from_url(encoded: &str) -> Result<ServerConfig, UrlParseError> {
        let parsed = Url::parse(encoded).map_err(UrlParseError::from)?;

        if parsed.scheme() != "ss" {
            return Err(UrlParseError::InvalidScheme);
        }

        let user_info = parsed.username();
        if user_info.is_empty() {
            // This maybe a QRCode URL, which is ss://BASE64-URL-ENCODE(pass:encrypt@hostname:port)

            let encoded = match parsed.host_str() {
                Some(e) => e,
                None => return Err(UrlParseError::MissingHost),
            };

            let mut decoded_body = match URL_PASSWORD_BASE64_ENGINE.decode(encoded) {
                Ok(b) => match String::from_utf8(b) {
                    Ok(b) => b,
                    Err(..) => return Err(UrlParseError::InvalidServerAddr),
                },
                Err(err) => {
                    error!("failed to parse legacy ss://ENCODED with Base64, err: {}", err);
                    return Err(UrlParseError::InvalidServerAddr);
                }
            };

            decoded_body.insert_str(0, "ss://");
            // Parse it like ss://method:password@host:port
            return ServerConfig::from_url(&decoded_body);
        }

        let (method, pwd) = match parsed.password() {
            Some(password) => {
                // Plain method:password without base64 encoded

                let m = match percent_encoding::percent_decode_str(user_info).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!("failed to parse percent-encoded method in userinfo, err: {}", err);
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                let p = match percent_encoding::percent_decode_str(password).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!("failed to parse percent-encoded password in userinfo, err: {}", err);
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                (m, p)
            }
            None => {
                // userinfo is not required to be percent encoded, but some implementation did.
                // If the base64 library have padding = added to the encoded string, then it will become %3D.

                let decoded_user_info = match percent_encoding::percent_decode_str(user_info).decode_utf8() {
                    Ok(m) => m,
                    Err(err) => {
                        error!("failed to parse percent-encoded userinfo, err: {}", err);
                        return Err(UrlParseError::InvalidAuthInfo);
                    }
                };

                // reborrow to fit AsRef<[u8]>
                let decoded_user_info: &str = &decoded_user_info;

                // Some implementation, like outline,
                // or those with Python (base64 in Python will still have '=' padding for URL safe encode)
                let account = match URL_PASSWORD_BASE64_ENGINE.decode(decoded_user_info) {
                    Ok(account) => match String::from_utf8(account) {
                        Ok(ac) => ac,
                        Err(..) => return Err(UrlParseError::InvalidAuthInfo),
                    },
                    Err(err) => {
                        error!("failed to parse UserInfo with Base64, err: {}", err);
                        return Err(UrlParseError::InvalidUserInfo);
                    }
                };

                let mut sp2 = account.splitn(2, ':');
                let (m, p) = match (sp2.next(), sp2.next()) {
                    (Some(m), Some(p)) => (m, p),
                    _ => return Err(UrlParseError::InvalidUserInfo),
                };

                (m.to_owned().into(), p.to_owned().into())
            }
        };

        let host = match parsed.host_str() {
            Some(host) => host,
            None => return Err(UrlParseError::MissingHost),
        };

        let port = parsed.port().unwrap_or(8388);
        let addr = format!("{host}:{port}");

        let addr = match addr.parse::<ServerAddr>() {
            Ok(a) => a,
            Err(err) => {
                error!("failed to parse \"{}\" to ServerAddr, err: {:?}", addr, err);
                return Err(UrlParseError::InvalidServerAddr);
            }
        };

        let method = method.parse().expect("method");
        let mut svrconfig = ServerConfig::new(addr, pwd, method);

        if let Some(q) = parsed.query() {
            let query = match serde_urlencoded::from_bytes::<Vec<(String, String)>>(q.as_bytes()) {
                Ok(q) => q,
                Err(err) => {
                    error!("failed to parse QueryString, err: {}", err);
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
                        let plugin = PluginConfig {
                            plugin: p.to_owned(),
                            plugin_opts: vsp.next().map(ToOwned::to_owned),
                            plugin_args: Vec::new(), // SIP002 doesn't have arguments for plugins
                        };
                        svrconfig.set_plugin(plugin);
                    }
                }
            }
        }

        if let Some(frag) = parsed.fragment() {
            svrconfig.set_remarks(frag);
        }

        Ok(svrconfig)
    }

    /// Check if it is a basic format server
    pub fn is_basic(&self) -> bool {
        self.remarks.is_none() && self.id.is_none()
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

impl FromStr for ServerConfig {
    type Err = UrlParseError;

    fn from_str(s: &str) -> Result<ServerConfig, Self::Err> {
        ServerConfig::from_url(s)
    }
}

/// Server address
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

/// Parse `ServerAddr` error
#[derive(Debug)]
pub struct ServerAddrError;

impl Display for ServerAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ServerAddr")
    }
}

impl FromStr for ServerAddr {
    type Err = ServerAddrError;

    fn from_str(s: &str) -> Result<ServerAddr, ServerAddrError> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(ServerAddr::SocketAddr(addr)),
            Err(..) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => {
                        if dn.is_empty() {
                            return Err(ServerAddrError);
                        }
                        match port.parse::<u16>() {
                            Ok(port) => Ok(ServerAddr::DomainName(dn.to_owned(), port)),
                            Err(..) => Err(ServerAddrError),
                        }
                    }
                    _ => Err(ServerAddrError),
                }
            }
        }
    }
}

impl Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ServerAddr::SocketAddr(ref a) => write!(f, "{a}"),
            ServerAddr::DomainName(ref d, port) => write!(f, "{d}:{port}"),
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

impl Display for ManagerAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ManagerAddr")
    }
}

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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ManagerAddr::SocketAddr(ref saddr) => fmt::Display::fmt(saddr, f),
            ManagerAddr::DomainName(ref dname, port) => write!(f, "{dname}:{port}"),
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

/// Policy for handling replay attack requests
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReplayAttackPolicy {
    /// Default strategy based on protocol
    ///
    /// SIP022 (AEAD-2022): Reject
    /// SIP004 (AEAD): Ignore
    /// Stream: Ignore
    Default,
    /// Ignore it completely
    Ignore,
    /// Try to detect replay attack and warn about it
    Detect,
    /// Try to detect replay attack and reject the request
    Reject,
}

impl Default for ReplayAttackPolicy {
    fn default() -> ReplayAttackPolicy {
        ReplayAttackPolicy::Default
    }
}

impl Display for ReplayAttackPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ReplayAttackPolicy::Default => f.write_str("default"),
            ReplayAttackPolicy::Ignore => f.write_str("ignore"),
            ReplayAttackPolicy::Detect => f.write_str("detect"),
            ReplayAttackPolicy::Reject => f.write_str("reject"),
        }
    }
}

/// Error while parsing ReplayAttackPolicy from string
#[derive(Debug, Clone, Copy)]
pub struct ReplayAttackPolicyError;

impl Display for ReplayAttackPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ReplayAttackPolicy")
    }
}

impl FromStr for ReplayAttackPolicy {
    type Err = ReplayAttackPolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(ReplayAttackPolicy::Default),
            "ignore" => Ok(ReplayAttackPolicy::Ignore),
            "detect" => Ok(ReplayAttackPolicy::Detect),
            "reject" => Ok(ReplayAttackPolicy::Reject),
            _ => Err(ReplayAttackPolicyError),
        }
    }
}
