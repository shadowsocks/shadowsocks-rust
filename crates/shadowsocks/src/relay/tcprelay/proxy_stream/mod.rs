//! Stream interface for communicating with shadowsocks proxy servers

// pub use self::{
//     client::{ProxyClientStream, ProxyClientStreamReadHalf, ProxyClientStreamWriteHalf},
//     server::{ProxyServerStream, ProxyServerStreamReadHalf, ProxyServerStreamWriteHalf},
// };

pub use self::{client::ProxyClientStream, server::ProxyServerStream};

pub mod client;
pub mod protocol;
pub mod server;
