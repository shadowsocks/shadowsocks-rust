//! Shadowsocks manager service
//!
//! Service for managing multiple relay servers. [Manage Multiple Users](https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users)

use std::io::{self, ErrorKind};
#[cfg(feature = "trust-dns")]
use std::sync::Arc;

use log::{trace, warn};
use shadowsocks::{
    config::ServerAddr,
    net::{AcceptOpts, ConnectOpts},
};

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

    #[cfg(feature = "trust-dns")]
    if config.dns.is_some() || crate::hint_support_default_system_resolver() {
        use shadowsocks::dns_resolver::DnsResolver;

        let r = match config.dns {
            None => DnsResolver::trust_dns_system_resolver(config.ipv6_first).await,
            Some(dns) => DnsResolver::trust_dns_resolver(dns, config.ipv6_first).await,
        };

        match r {
            Ok(r) => {
                manager.set_dns_resolver(Arc::new(r));
            }
            Err(err) => {
                warn!(
                    "initialize DNS resolver failed, fallback to system resolver, error: {}",
                    err
                );
            }
        }
    }

    let mut connect_opts = ConnectOpts {
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

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
        bind_interface: config.outbound_bind_interface,

        ..Default::default()
    };

    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    connect_opts.tcp.nodelay = config.no_delay;

    let mut accept_opts = AcceptOpts::default();
    accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
    accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
    accept_opts.tcp.nodelay = config.no_delay;

    manager.set_connect_opts(connect_opts);
    manager.set_accept_opts(accept_opts);

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
