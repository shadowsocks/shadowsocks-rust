//! TLS support for HTTP local (HTTPS)
//!
//! Choosing TLS library by `local-http-rustls` and `local-http-native-tls`

#[cfg(feature = "local-http-native-tls")]
pub mod native_tls;

#[cfg(feature = "local-http-native-tls")]
pub use self::native_tls::{TlsAcceptor, TlsStream};

#[cfg(feature = "local-http-rustls")]
pub mod rustls;

#[cfg(feature = "local-http-rustls")]
pub use self::rustls::{TlsAcceptor, TlsStream};
