//! Shadowsocks Local HTTP proxy server
//!
//! https://www.ietf.org/rfc/rfc2068.txt

pub use self::server::{Http, HttpBuilder, HttpConnectionHandler};

mod http_client;
mod http_service;
mod http_stream;
pub mod server;
mod tokio_rt;
mod utils;
