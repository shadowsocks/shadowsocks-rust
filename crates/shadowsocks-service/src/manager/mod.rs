//! Shadowsocks manager service
//!
//! Service for managing multiple relay servers. [Manage Multiple Users](https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users)

use std::{
    io::{self, ErrorKind},
    sync::Arc,
};

use log::{trace, warn};
use shadowsocks::{config::ServerAddr, net::ConnectOpts};

use crate::config::{Config, ConfigType};

pub use self::server::Manager;

pub mod server;

/// Starts a manager server
pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Manager);

    trace!("{:?}", config);

    #[cfg(unix)]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    let mut manager = Manager::new(config.manager.expect("missing manager config"));
    manager.set_mode(config.mode);
    manager.set_nodelay(config.no_delay);

    #[cfg(feature = "trust-dns")]
    {
        use shadowsocks::dns_resolver::DnsResolver;

        let resolver = Arc::new(DnsResolver::trust_dns_resolver(config.dns, config.ipv6_first).await?);
        manager.set_dns_resolver(resolver);
    }

    let connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        bind_local_addr: match config.local_addr {
            None => None,
            Some(ServerAddr::SocketAddr(sa)) => Some(sa.ip()),
            Some(ServerAddr::DomainName(..)) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "local_addr must be a SocketAddr",
                ));
            }
        },

        #[cfg(any(target_os = "linux", target_os = "android"))]
        bind_interface: config.outbound_bind_interface,

        ..Default::default()
    };
    manager.set_connect_opts(connect_opts);

    if let Some(c) = config.udp_max_associations {
        manager.set_udp_capacity(c);
    }

    if let Some(d) = config.udp_timeout {
        manager.set_udp_expiry_duration(d);
    }

    for svr_cfg in config.server {
        manager.add_server(svr_cfg, None).await;
    }

    manager.run().await
}
