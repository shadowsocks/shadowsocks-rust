//! Customized DNS resolver

pub use self::{
    config::NameServerAddr,
    server::{Dns, DnsBuilder},
};

mod client_cache;
pub mod config;
pub mod dns_resolver;
pub mod server;
mod upstream;
