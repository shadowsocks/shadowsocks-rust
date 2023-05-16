//! Fake DNS
//!
//! Start a DNS resolver server, mapping requested names to local private network addresses.
//! When local server receives proxy request with those mapped addresses, it could translate
//! it back to the original domain names.
//!
//! It normally cooperates with `local-redir` and `local-tun`.

pub use self::server::{FakeDns, FakeDnsBuilder};

pub mod manager;
mod processor;
mod proto;
pub mod server;
mod tcp_server;
mod udp_server;
