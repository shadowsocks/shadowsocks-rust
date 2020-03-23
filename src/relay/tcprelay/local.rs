//! Relay for TCP server that running on local environment

use std::io;

use crate::{config::ConfigType, context::SharedContext};

/// Starts a TCP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    match context.config().config_type {
        ConfigType::TunnelLocal => super::tunnel_local::run(context).await,
        ConfigType::Socks5Local => super::socks5_local::run(context).await,
        #[cfg(feature = "local-protocol-http")]
        ConfigType::HttpLocal => super::http_local::run(context).await,
        ConfigType::RedirLocal => super::redir_local::run(context).await,
        ConfigType::DnsLocal => unreachable!(),
        ConfigType::Server => unreachable!(),
        ConfigType::Manager => unreachable!(),
    }
}
