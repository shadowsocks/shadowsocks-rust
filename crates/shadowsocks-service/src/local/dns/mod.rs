//! Customized DNS resolver

pub use self::server::Dns;

pub mod client_cache;
pub mod config;
pub mod dns_resolver;
pub mod server;
pub mod upstream;
