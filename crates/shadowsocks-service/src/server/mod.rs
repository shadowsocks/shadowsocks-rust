//! Shadowsocks server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
};

use futures::{future, FutureExt};
use log::{trace, warn};
#[cfg(feature = "trust-dns")]
use shadowsocks::dns_resolver::DnsResolver;
use shadowsocks::{
    config::ServerAddr,
    net::{AcceptOpts, ConnectOpts},
};

use crate::config::{Config, ConfigType};

pub use self::server::Server;

pub mod context;
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

        #[cfg(any(target_os = "linux", target_os = "android"))]
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

    #[cfg(feature = "trust-dns")]
    let resolver = if config.dns.is_some() || crate::hint_support_default_system_resolver() {
        Some(Arc::new(
            DnsResolver::trust_dns_resolver(config.dns, config.ipv6_first).await?,
        ))
    } else {
        None
    };

    let acl = config.acl.map(Arc::new);

    for svr_cfg in config.server {
        let mut server = Server::new(svr_cfg);

        #[cfg(feature = "trust-dns")]
        if let Some(ref r) = resolver {
            server.set_dns_resolver(r.clone());
        }

        server.set_connect_opts(connect_opts.clone());
        server.set_accept_opts(accept_opts.clone());

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

        if let Some(ref acl) = acl {
            server.set_acl(acl.clone());
        }

        servers.push(server);
    }

    let mut vfut = Vec::with_capacity(servers.len());
    for server in servers {
        vfut.push(server.run().boxed());
    }

    let (res, ..) = future::select_all(vfut).await;
    res
}
