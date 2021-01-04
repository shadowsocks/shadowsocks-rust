//! Customized DNS resolver

pub use self::{config::NameServerAddr, server::Dns};

mod client_cache;
pub mod config;
pub mod server;
mod upstream;
