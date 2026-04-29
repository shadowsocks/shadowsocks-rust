//! Standalone SOCKS5 clients used by the local SOCKS server and tests.

pub use self::{tcp_client::Socks5TcpClient, udp_client::Socks5UdpClient};

pub mod tcp_client;
pub mod udp_client;
