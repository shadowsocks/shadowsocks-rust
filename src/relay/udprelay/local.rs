//! UDP local relay server

use std::io;

use crate::{config::ConfigType, context::SharedContext};

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    match context.config().config_type {
        #[cfg(feature = "local-tunnel")]
        ConfigType::TunnelLocal => super::tunnel_local::run(context).await,
        ConfigType::Socks5Local => super::socks5_local::run(context).await,
        #[cfg(feature = "local-redir")]
        ConfigType::RedirLocal => super::redir_local::run(context).await,
        #[cfg(feature = "local-http")]
        ConfigType::HttpLocal => unreachable!(),
        #[cfg(feature = "local-dns-relay")]
        ConfigType::DnsLocal => unreachable!(),
        ConfigType::Server => unreachable!(),
        ConfigType::Manager => unreachable!(),
    }
}
