//! Relay for TCP server that running on local environment

use std::io;

use crate::{config::ConfigType, context::SharedContext};

/// Starts a TCP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    match context.config().config_type {
        ConfigType::Socks5Local => super::socks5_local::run(context).await,
        #[cfg(feature = "local-socks4")]
        ConfigType::Socks4Local => super::socks4_local::run(context).await,
        #[cfg(feature = "local-tunnel")]
        ConfigType::TunnelLocal => super::tunnel_local::run(context).await,
        #[cfg(feature = "local-http")]
        ConfigType::HttpLocal => super::http_local::run(context).await,
        #[cfg(feature = "local-redir")]
        ConfigType::RedirLocal => super::redir_local::run(context).await,
        #[cfg(feature = "local-dns-relay")]
        ConfigType::DnsLocal => unreachable!(),
        ConfigType::Server => unreachable!(),
        ConfigType::Manager => unreachable!(),
    }
}
