//! Shadowsocks server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
};

use futures::{future, FutureExt};
use log::{trace, warn};
use shadowsocks::{config::ServerAddr, dns_resolver::DnsResolver, net::ConnectOpts};

use crate::config::{Config, ConfigType};

pub use self::server::Server;

pub mod server;
mod tcprelay;
mod udprelay;

/// Starts a shadowsocks server
pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Server);
    assert!(config.server.len() > 0);

    trace!("{:?}", config);

    #[cfg(unix)]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    let mut servers = Vec::new();

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

    #[cfg(feature = "trust-dns")]
    let resolver = Arc::new(DnsResolver::trust_dns_resolver(config.dns, config.ipv6_first).await?);

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
