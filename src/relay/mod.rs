//! Relay server in local and server side implementations.

pub(crate) mod dns_resolver;
#[cfg(feature = "local-dns-relay")]
pub mod dnsrelay;
pub(crate) mod flow;
pub(crate) mod loadbalancing;
pub mod local;
pub mod manager;
#[cfg(feature = "local-redir")]
pub(crate) mod redir;
pub mod server;
#[cfg(feature = "local-socks4")]
pub mod socks4;
pub mod socks5;
pub(crate) mod sys;
pub mod tcprelay;
pub mod udprelay;
pub(crate) mod utils;
