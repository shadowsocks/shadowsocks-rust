//! UDP local relay server

use std::io;

use super::{redir_local, socks5_local, tunnel_local};
use crate::{config::ConfigType, context::SharedContext};

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    match context.config().config_type {
        ConfigType::TunnelLocal => tunnel_local::run(context).await,
        ConfigType::Socks5Local => socks5_local::run(context).await,
        ConfigType::RedirLocal => redir_local::run(context).await,
        ConfigType::HttpLocal => unreachable!(),
        ConfigType::DnsLocal => unreachable!(),
        ConfigType::Server => unreachable!(),
        ConfigType::Manager => unreachable!(),
    }
}
