//! UDP local relay server

use std::{
    io::{self, Error, ErrorKind},
    time::Duration,
};

use crate::{config::ConfigType, context::SharedContext};

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    if let Some(0) = context.config().udp_max_associations {
        let err = Error::new(ErrorKind::Other, "udp_max_association shouldn't be 0");
        return Err(err);
    }

    if context.config().udp_timeout == Some(Duration::from_secs(0)) {
        let err = Error::new(ErrorKind::Other, "udp_timeout shouldn't be 0");
        return Err(err);
    }

    match context.config().config_type {
        ConfigType::Socks5Local => super::socks5_local::run(context).await,
        #[cfg(feature = "local-socks4")]
        ConfigType::Socks4Local => unreachable!(),
        #[cfg(feature = "local-tunnel")]
        ConfigType::TunnelLocal => super::tunnel_local::run(context).await,
        #[cfg(feature = "local-redir")]
        ConfigType::RedirLocal => super::redir_local::run(context).await,
        #[cfg(feature = "local-http")]
        ConfigType::HttpLocal => unreachable!(),
        #[cfg(all(
            feature = "local-http",
            any(feature = "local-http-native-tls", feature = "local-http-rustls")
        ))]
        ConfigType::HttpsLocal => unreachable!(),
        #[cfg(feature = "local-dns")]
        ConfigType::DnsLocal => unreachable!(),
        ConfigType::Server => unreachable!(),
        ConfigType::Manager => unreachable!(),
    }
}
