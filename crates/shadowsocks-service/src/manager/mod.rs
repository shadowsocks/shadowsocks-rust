//! Shadowsocks manager service
//!
//! Service for managing multiple relay servers. [Manage Multiple Users](https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users)

use std::{io, net::SocketAddr, sync::Arc};

use log::trace;
use shadowsocks::net::{AcceptOpts, ConnectOpts};

use crate::{
    config::{Config, ConfigType},
    dns::build_dns_resolver,
    server::SERVER_DEFAULT_KEEPALIVE_TIMEOUT,
};

pub use self::server::{Manager, ManagerBuilder};

pub mod server;

/// Starts a manager server
pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Manager);

    trace!("{:?}", config);

    #[cfg(all(unix, not(target_os = "android")))]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            log::warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    let mut manager_builder = ManagerBuilder::new(config.manager.expect("missing manager config"));

    let mut connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        bind_local_addr: config.outbound_bind_addr.map(|ip| SocketAddr::new(ip, 0)),
        bind_interface: config.outbound_bind_interface,

        ..Default::default()
    };

    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    connect_opts.tcp.nodelay = config.no_delay;
    connect_opts.tcp.fastopen = config.fast_open;
    connect_opts.tcp.keepalive = config.keep_alive.or(Some(SERVER_DEFAULT_KEEPALIVE_TIMEOUT));
    connect_opts.tcp.mptcp = config.mptcp;
    connect_opts.udp.mtu = config.udp_mtu;
    connect_opts.udp.allow_fragmentation = config.outbound_udp_allow_fragmentation;

    let mut accept_opts = AcceptOpts {
        ipv6_only: config.ipv6_only,
        ..Default::default()
    };
    accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
    accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
    accept_opts.tcp.nodelay = config.no_delay;
    accept_opts.tcp.fastopen = config.fast_open;
    accept_opts.tcp.keepalive = config.keep_alive.or(Some(SERVER_DEFAULT_KEEPALIVE_TIMEOUT));
    accept_opts.tcp.mptcp = config.mptcp;
    accept_opts.udp.mtu = config.udp_mtu;

    if let Some(resolver) =
        build_dns_resolver(config.dns, config.ipv6_first, config.dns_cache_size, &connect_opts).await
    {
        manager_builder.set_dns_resolver(Arc::new(resolver));
    }
    manager_builder.set_ipv6_first(config.ipv6_first);

    manager_builder.set_connect_opts(connect_opts);
    manager_builder.set_accept_opts(accept_opts);

    if let Some(c) = config.udp_max_associations {
        manager_builder.set_udp_capacity(c);
    }

    if let Some(d) = config.udp_timeout {
        manager_builder.set_udp_expiry_duration(d);
    }

    if let Some(acl) = config.acl {
        manager_builder.set_acl(Arc::new(acl));
    }

    let manager = manager_builder.build().await?;

    for svr_inst in config.server {
        manager.add_server(svr_inst.config).await;
    }

    manager.run().await
}
