//! SOCK protocol configuration

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};

use log::trace;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct SSSocks5AuthPasswordUserConfig {
    user_name: String,
    password: String,
}

#[derive(Deserialize, Debug)]
struct SSSocks5AuthPasswordConfig {
    users: Vec<SSSocks5AuthPasswordUserConfig>,
}

#[derive(Deserialize, Debug)]
struct SSSocks5AuthConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<SSSocks5AuthPasswordConfig>,
}

/// SOCKS5 Authentication method
#[derive(Debug, Clone)]
pub struct Socks5AuthConfig {
    pub passwd: Socks5AuthPasswdConfig,
}

impl Socks5AuthConfig {
    /// Create a new SOCKS5 Authentication configuration
    pub fn new() -> Self {
        Self {
            passwd: Socks5AuthPasswdConfig::new(),
        }
    }

    /// Load from configuration file
    ///
    /// ```json
    /// {
    ///     "password": {
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

        let jconf: SSSocks5AuthConfig = match json5::from_str(&content) {
            Ok(c) => c,
            Err(err) => return Err(io::Error::other(err)),
        };

        let mut passwd = Socks5AuthPasswdConfig::new();
        if let Some(p) = jconf.password {
            for user in p.users {
                passwd.add_user(user.user_name, user.password);
            }
        }

        Ok(Self { passwd })
    }

    /// Check if authentication is required
    pub fn auth_required(&self) -> bool {
        self.passwd.total_users() > 0
    }
}

impl Default for Socks5AuthConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// SOCKS5 server User/Password Authentication configuration
///
/// RFC1929 https://datatracker.ietf.org/doc/html/rfc1929
#[derive(Debug, Clone)]
pub struct Socks5AuthPasswdConfig {
    passwd: HashMap<String, String>,
}

impl Socks5AuthPasswdConfig {
    /// Create an empty `Passwd` configuration
    pub fn new() -> Self {
        Self { passwd: HashMap::new() }
    }

    /// Add a user with password
    pub fn add_user<U, P>(&mut self, user_name: U, password: P)
    where
        U: Into<String>,
        P: Into<String>,
    {
        self.passwd.insert(user_name.into(), password.into());
    }

    /// Check if `user_name` exists and validate `password`
    pub fn check_user<U, P>(&self, user_name: U, password: P) -> bool
    where
        U: AsRef<str>,
        P: AsRef<str>,
    {
        match self.passwd.get(user_name.as_ref()) {
            Some(pwd) => pwd == password.as_ref(),
            None => false,
        }
    }

    /// Total users
    pub fn total_users(&self) -> usize {
        self.passwd.len()
    }
}

impl Default for Socks5AuthPasswdConfig {
    fn default() -> Self {
        Self::new()
    }
}
