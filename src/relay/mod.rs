//! Relay server in local and server side implementations.

pub(crate) mod dns_resolver;
#[cfg(target_os = "android")]
pub mod dnsrelay;
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
