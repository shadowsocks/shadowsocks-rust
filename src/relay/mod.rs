//! Relay server in local and server side implementations.

#[cfg(feature = "dns-relay")]
pub mod dnsrelay;
pub(crate) mod dns_resolver;
pub(crate) mod flow;
pub(crate) mod loadbalancing;
pub mod local;
pub mod manager;
pub(crate) mod redir;
pub mod server;
pub mod socks5;
pub(crate) mod sys;
pub mod tcprelay;
pub mod udprelay;
pub(crate) mod utils;
