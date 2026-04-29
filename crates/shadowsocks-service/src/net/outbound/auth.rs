//! Outbound proxy authentication primitives.
//!
//! These types replace the previous ad-hoc `Option<(&[u8], &[u8])>` /
//! `Option<(&str, &str)>` parameters used by the SOCKS5 and HTTP CONNECT
//! clients, leaving room for additional authentication mechanisms in the
//! future without breaking the public API again.

use std::fmt::{self, Debug, Formatter};

/// SOCKS5 client authentication method.
///
/// Currently only the two methods defined by the original SOCKS5 RFC suite
/// (RFC1928 / RFC1929) are implemented. The enum is marked
/// `#[non_exhaustive]` so additional variants (GSSAPI, CHAP, ...) can be
/// added without breaking downstream code.
#[derive(Clone)]
#[non_exhaustive]
pub enum Socks5Auth {
    /// `NO AUTHENTICATION REQUIRED` (method 0x00, RFC1928).
    None,
    /// `USERNAME/PASSWORD` (method 0x02, RFC1929).
    UsernamePassword {
        /// Username, 1..=255 bytes.
        username: Vec<u8>,
        /// Password, 1..=255 bytes.
        password: Vec<u8>,
    },
}

impl Socks5Auth {
    /// Construct an unauthenticated configuration.
    pub const fn none() -> Self {
        Self::None
    }

    /// Construct a username/password authentication configuration.
    pub fn username_password<U, P>(username: U, password: P) -> Self
    where
        U: Into<Vec<u8>>,
        P: Into<Vec<u8>>,
    {
        Self::UsernamePassword {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Returns `true` when no authentication is required.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl Debug for Socks5Auth {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.debug_tuple("Socks5Auth::None").finish(),
            Self::UsernamePassword { username, .. } => f
                .debug_struct("Socks5Auth::UsernamePassword")
                .field("username", &String::from_utf8_lossy(username).into_owned())
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}

/// HTTP / HTTPS proxy authentication.
///
/// Currently only Basic authentication (RFC7617) is implemented. The enum
/// is marked `#[non_exhaustive]` so additional schemes (Bearer, Digest,
/// Negotiate, ...) can be added without breaking downstream code.
#[derive(Clone)]
#[non_exhaustive]
pub enum HttpProxyAuth {
    /// No `Proxy-Authorization` header is sent.
    None,
    /// Standard `Basic <base64(user:pass)>` authentication.
    Basic { username: String, password: String },
}

impl HttpProxyAuth {
    /// Construct an unauthenticated configuration.
    pub const fn none() -> Self {
        Self::None
    }

    /// Construct a Basic authentication configuration.
    pub fn basic<U, P>(username: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        Self::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Returns `true` when no authentication is required.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl Debug for HttpProxyAuth {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.debug_tuple("HttpProxyAuth::None").finish(),
            Self::Basic { username, .. } => f
                .debug_struct("HttpProxyAuth::Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
        }
    }
}
