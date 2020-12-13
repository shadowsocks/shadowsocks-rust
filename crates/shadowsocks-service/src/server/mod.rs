//! Shadowsocks server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
};

use futures::{future, FutureExt};
use log::trace;
#[cfg(feature = "trust-dns")]
use shadowsocks::dns_resolver::create_resolver;
use shadowsocks::net::ConnectOpts;

use crate::config::{Config, ConfigType};

pub use self::server::Server;

pub mod server;
mod tcprelay;
mod udprelay;

/// Run all servers in `Config`
pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Server);
    assert!(config.server.len() > 0);

    trace!("starting shadowsocks server with config: {:?}", config);

    let mut servers = Vec::new();

    let connect_opts = Arc::new(ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        ..Default::default()
    });

    #[cfg(feature = "trust-dns")]
    let resolver = Arc::new(create_resolver(config.dns, config.ipv6_first).await?);

    let acl = config.acl.map(Arc::new);

    for svr_cfg in config.server {
        let mut server = Server::new(svr_cfg);

        #[cfg(feature = "trust-dns")]
        server.set_dns_resolver(resolver.clone());

        server.set_connect_opts(connect_opts.clone());
        if let Some(c) = config.udp_max_associations {
            server.set_udp_capacity(c);
        }
        if let Some(d) = config.udp_timeout {
            server.set_udp_expiry_duration(d);
        }
        server.set_mode(config.mode);
        if let Some(ref m) = config.manager {
            server.set_manager_addr(m.addr.clone());
        }
        if config.no_delay {
            server.set_nodelay(true);
        }

        if let Some(ref acl) = acl {
            server.set_acl(acl.clone());
        }

        servers.push(server);
    }

    let mut vfut = Vec::with_capacity(servers.len());
    for server in servers {
        vfut.push(server.run().boxed());
    }

    let _ = future::select_all(vfut).await;

    let err = io::Error::new(ErrorKind::Other, "one of the servers exited unexpectly");
    Err(err)
}
