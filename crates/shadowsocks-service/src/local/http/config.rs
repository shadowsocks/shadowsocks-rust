//! HTTP protocol configuration

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};

use base64::Engine as _;
use log::trace;
use serde::Deserialize;

const BASIC_AUTH_BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

#[derive(Deserialize, Debug)]
struct SSHttpAuthBasicUserConfig {
    user_name: String,
    password: String,
}

#[derive(Deserialize, Debug)]
struct SSHttpAuthBasicConfig {
    users: Vec<SSHttpAuthBasicUserConfig>,
}

#[derive(Deserialize, Debug)]
struct SSHttpAuthConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    basic: Option<SSHttpAuthBasicConfig>,
}

/// HTTP Authentication method
#[derive(Debug, Clone)]
pub struct HttpAuthConfig {
    pub basic: HttpAuthBasicConfig,
}

impl HttpAuthConfig {
    /// Create a new HTTP Authentication configuration
    pub fn new() -> Self {
        Self {
            basic: HttpAuthBasicConfig::new(),
        }
    }

    /// Load from configuration file
    ///
    /// ```json
    /// {
    ///     "basic": {
    ///         "users": [
    ///             {
    ///                 "user_name": "USER_NAME",
    ///                 "password": "PASSWORD"
    ///             }
    ///         ]
    ///      }
    /// }
    pub fn load_from_file<P: AsRef<Path> + ?Sized>(filename: &P) -> io::Result<Self> {
        let filename = filename.as_ref();

        trace!(
            "loading socks5 authentication configuration from {}",
            filename.display()
        );

        let mut reader = OpenOptions::new().read(true).open(filename)?;
        let mut content = String::new();
        reader.read_to_string(&mut content)?;

        let jconf: SSHttpAuthConfig = match json5::from_str(&content) {
            Ok(c) => c,
            Err(err) => return Err(io::Error::other(err)),
        };

        let mut basic = HttpAuthBasicConfig::new();
        if let Some(p) = jconf.basic {
            for user in p.users {
                basic.add_user(user.user_name, user.password);
            }
        }

        Ok(Self { basic })
    }

    /// Check if authentication is required
    pub fn auth_required(&self) -> bool {
        self.basic.total_users() > 0
    }

    /// Check Basic Authentication
    pub fn verify_basic_auth(&self, header_value: &str) -> bool {
        const BASIC_PREFIX: &str = "Basic ";

        if !header_value.starts_with(BASIC_PREFIX) {
            return false;
        }
        let b64_encoded = &header_value[BASIC_PREFIX.len()..];
        let decoded_bytes = match BASIC_AUTH_BASE64_ENGINE.decode(b64_encoded) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let decoded_str = match String::from_utf8(decoded_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let (user_name, password) = match decoded_str.split_once(':') {
            Some((u, p)) => (u, p),
            None => return false,
        };
        self.basic.check_user(user_name, password)
    }
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP server User/Password Authentication configuration
///
/// RFC9110 https://httpwg.org/specs/rfc9110.html#auth.client.proxy
#[derive(Debug, Clone)]
pub struct HttpAuthBasicConfig {
    users: HashMap<String, String>,
}

impl HttpAuthBasicConfig {
    /// Create an empty `Passwd` configuration
    pub fn new() -> Self {
        Self { users: HashMap::new() }
    }

    /// Add a user with password
    pub fn add_user<U, P>(&mut self, user_name: U, password: P)
    where
        U: Into<String>,
        P: Into<String>,
    {
        self.users.insert(user_name.into(), password.into());
    }

    /// Check if `user_name` exists and validate `password`
    pub fn check_user<U, P>(&self, user_name: U, password: P) -> bool
    where
        U: AsRef<str>,
        P: AsRef<str>,
    {
        match self.users.get(user_name.as_ref()) {
            Some(pwd) => pwd == password.as_ref(),
            None => false,
        }
    }

    /// Total users
    pub fn total_users(&self) -> usize {
        self.users.len()
    }
}

impl Default for HttpAuthBasicConfig {
    fn default() -> Self {
        Self::new()
    }
}
