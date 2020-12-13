//! Shadowsocks manager service
//!
//! Service for managing multiple relay servers. [Manage Multiple Users](https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users)

use std::{io, sync::Arc};

use shadowsocks::net::ConnectOpts;

use crate::config::{Config, ConfigType};

pub use self::server::Manager;

pub mod server;

pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Manager);

    let mut manager = Manager::new(config.manager.expect("missing manager config"));
    manager.set_mode(config.mode);
    manager.set_nodelay(config.no_delay);

    #[cfg(feature = "trust-dns")]
    {
        use shadowsocks::dns_resolver::create_resolver;

        let resolver = Arc::new(create_resolver(config.dns, config.ipv6_first).await?);
        manager.set_dns_resolver(resolver);
    }

    let connect_opts = Arc::new(ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        ..Default::default()
    });
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
