//! Shadowsocks SOCKS (4/4a, 5) Local Server

pub use self::server::Socks;

pub mod client;
pub mod server;
pub mod socks4;
mod socks4_server;
mod socks5_server;
