//! Relay for TCP server that running on local environment

use std::io;

use crate::{config::ConfigType, context::SharedContext};

use super::{http_local, redir_local, socks5_local, tunnel_local};

/// Starts a TCP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    match context.config().config_type {
        ConfigType::TunnelLocal => tunnel_local::run(context).await,
        ConfigType::Socks5Local => socks5_local::run(context).await,
        ConfigType::HttpLocal => http_local::run(context).await,
        ConfigType::RedirLocal => redir_local::run(context).await,
        ConfigType::Server => unreachable!(),
        ConfigType::Manager => unreachable!(),
    }
}
