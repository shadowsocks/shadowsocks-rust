//! Shadowsocks Local Server

use std::{io, sync::Arc};

use log::trace;
use shadowsocks::{dns_resolver::DnsResolver, net::ConnectOpts};

use crate::config::{Config, ConfigType, ProtocolType};

use self::context::ServiceContext;

pub mod acl;
mod context;
#[cfg(feature = "local-dns")]
mod dns;
#[cfg(feature = "local-http")]
mod http;
mod loadbalancing;
mod net;
#[cfg(feature = "local-redir")]
mod redir;
mod socks;
#[cfg(feature = "local-tunnel")]
mod tunnel;
mod utils;

pub async fn run(config: Config) -> io::Result<()> {
    assert!(config.config_type == ConfigType::Local && config.local_addr.is_some());
    assert!(config.server.len() > 0);

    trace!("{:?}", config);

    let mut context = ServiceContext::new();
    context.set_connect_opts(ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        ..Default::default()
    });

    #[cfg(feature = "trust-dns")]
    context.set_dns_resolver(Arc::new(
        DnsResolver::trust_dns_resolver(config.dns, config.ipv6_first).await?,
    ));

    if let Some(acl) = config.acl {
        context.set_acl(acl);
    }

    let client_config = config.local_addr.expect("local server requires local address");

    let context = Arc::new(context);

    match config.local_protocol {
        ProtocolType::Socks => {
            use self::socks::Socks;

            let mut server = Socks::with_context(context, client_config, config.server);

            if let Some(c) = config.udp_max_associations {
                server.set_udp_capacity(c);
            }
            if let Some(d) = config.udp_timeout {
                server.set_udp_expiry_duration(d);
            }
            if config.no_delay {
                server.set_nodelay(true);
            }

            server.run().await
        }
        #[cfg(feature = "local-tunnel")]
        ProtocolType::Tunnel => {
            use self::tunnel::Tunnel;

            let forward_addr = config.forward.expect("tunnel requires forward address");

            let mut server = Tunnel::with_context(context, client_config, config.server, forward_addr);

            if let Some(c) = config.udp_max_associations {
                server.set_udp_capacity(c);
            }
            if let Some(d) = config.udp_timeout {
                server.set_udp_expiry_duration(d);
            }
            server.set_mode(config.mode);
            if config.no_delay {
                server.set_nodelay(true);
            }

            server.run().await
        }
        #[cfg(feature = "local-http")]
        ProtocolType::Http => {
            use self::http::Http;

            let server = Http::with_context(context, client_config, config.server);
            server.run().await
        }
        #[cfg(feature = "local-redir")]
        ProtocolType::Redir => {
            use self::redir::Redir;

            let mut server = Redir::with_context(context, client_config, config.server);
            if let Some(c) = config.udp_max_associations {
                server.set_udp_capacity(c);
            }
            if let Some(d) = config.udp_timeout {
                server.set_udp_expiry_duration(d);
            }
            server.set_mode(config.mode);
            if config.no_delay {
                server.set_nodelay(true);
            }
            server.set_tcp_redir(config.tcp_redir);
            server.set_udp_redir(config.udp_redir);

            server.run().await
        }
        #[cfg(feature = "local-dns")]
        ProtocolType::Dns => unimplemented!(),
    }
}
