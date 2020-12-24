//! Customized DNS resolver

pub use self::server::Dns;

mod client_cache;
pub mod server;
mod upstream;
