//! TCP relay

pub use self::{
    proxy_listener::ProxyListener,
    proxy_stream::{ProxyClientStream, ProxyServerStream},
};

#[cfg(feature = "aead-cipher")]
mod aead;
#[cfg(feature = "aead-cipher-2022")]
mod aead_2022;
pub mod crypto_io;
pub mod proxy_listener;
pub mod proxy_stream;
#[cfg(feature = "stream-cipher")]
mod stream;
pub mod utils;

/// Connection direction type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Connection initiated from client to server
    Client,
    /// Connection initiated from server to client
    Server,
}
