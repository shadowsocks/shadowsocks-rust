//! Shadowsocks server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures::future;
use log::trace;
use shadowsocks::net::{AcceptOpts, ConnectOpts, UdpSocketOpts};

use crate::{
    config::{Config, ConfigType},
    dns::build_dns_resolver,
    utils::ServerHandle,
};

pub use self::{
    server::{Server, ServerBuilder},
    tcprelay::TcpServer,
    udprelay::UdpServer,
};

pub mod context;
#[allow(clippy::module_inception)]
pub mod server;
mod tcprelay;
mod udprelay;

/// Default TCP Keep Alive timeout
///
/// This is borrowed from Go's `net` library's default setting
pub(crate) const SERVER_DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Starts a shadowsocks server
pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Server);
    assert!(!config.server.is_empty());

    trace!("{:?}", config);

    // Warning for Stream Ciphers
    #[cfg(feature = "stream-cipher")]
    for inst in config.server.iter() {
        let server = &inst.config;

        if server.method().is_stream() {
            log::warn!(
                "stream cipher {} for server {} have inherent weaknesses (see discussion in https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                    DO NOT USE. It will be removed in the future.",
                server.method(),
                server.addr()
            );
        }
    }

    #[cfg(all(unix, not(target_os = "android")))]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            log::warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    let mut servers = Vec::new();

    let mut connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,
        #[cfg(target_os = "freebsd")]
        user_cookie: config.outbound_user_cookie,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        bind_local_addr: config.outbound_bind_addr.map(|ip| SocketAddr::new(ip, 0)),
        bind_interface: config.outbound_bind_interface,

        udp: UdpSocketOpts {
            allow_fragmentation: config.outbound_udp_allow_fragmentation,

            ..Default::default()
        },

        ..Default::default()
    };

    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    connect_opts.tcp.nodelay = config.no_delay;
    connect_opts.tcp.fastopen = config.fast_open;
    connect_opts.tcp.keepalive = config.keep_alive.or(Some(SERVER_DEFAULT_KEEPALIVE_TIMEOUT));
    connect_opts.tcp.mptcp = config.mptcp;
    connect_opts.udp.mtu = config.udp_mtu;

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

    let resolver = build_dns_resolver(config.dns, config.ipv6_first, config.dns_cache_size, &connect_opts)
        .await
        .map(Arc::new);

    let acl = config.acl.map(Arc::new);

    for inst in config.server {
        let svr_cfg = inst.config;
        let mut server_builder = ServerBuilder::new(svr_cfg);

        if let Some(ref r) = resolver {
            server_builder.set_dns_resolver(r.clone());
        }

        let mut connect_opts = connect_opts.clone();
        let accept_opts = accept_opts.clone();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(fwmark) = inst.outbound_fwmark {
            connect_opts.fwmark = Some(fwmark);
        }

        #[cfg(target_os = "freebsd")]
        if let Some(user_cookie) = inst.outbound_user_cookie {
            connect_opts.user_cookie = Some(user_cookie);
        }

        if let Some(bind_local_addr) = inst.outbound_bind_addr {
            connect_opts.bind_local_addr = Some(SocketAddr::new(bind_local_addr, 0));
        }

        if let Some(bind_interface) = inst.outbound_bind_interface {
            connect_opts.bind_interface = Some(bind_interface);
        }

        if let Some(udp_allow_fragmentation) = inst.outbound_udp_allow_fragmentation {
            connect_opts.udp.allow_fragmentation = udp_allow_fragmentation;
        }

        server_builder.set_connect_opts(connect_opts);
        server_builder.set_accept_opts(accept_opts);

        if let Some(c) = config.udp_max_associations {
            server_builder.set_udp_capacity(c);
        }
        if let Some(d) = config.udp_timeout {
            server_builder.set_udp_expiry_duration(d);
        }
        if let Some(ref m) = config.manager {
            server_builder.set_manager_addr(m.addr.clone());
        }

        match inst.acl {
            Some(acl) => server_builder.set_acl(Arc::new(acl)),
            None => {
                if let Some(ref acl) = acl {
                    server_builder.set_acl(acl.clone());
                }
            }
        }

        if config.ipv6_first {
            server_builder.set_ipv6_first(config.ipv6_first);
        }

        server_builder.set_security_config(&config.security);

        let server = server_builder.build().await?;
        servers.push(server);
    }

    if servers.len() == 1 {
        let server = servers.pop().unwrap();
        return server.run().await;
    }

    let mut vfut = Vec::with_capacity(servers.len());

    for server in servers {
        vfut.push(ServerHandle(tokio::spawn(async move { server.run().await })));
    }

    let (res, ..) = future::select_all(vfut).await;
    res
}
