//! Shadowsocks Local Server

use std::{io, sync::Arc};

use log::{trace, warn};
use shadowsocks::{dns_resolver::DnsResolver, net::ConnectOpts};

use crate::config::{Config, ConfigType, Mode, ProtocolType};

use self::context::ServiceContext;
#[cfg(feature = "local-dns")]
use self::dns::dns_resolver::DnsResolver as LocalDnsResolver;

pub mod acl;
pub mod context;
#[cfg(feature = "local-dns")]
pub mod dns;
#[cfg(feature = "local-http")]
pub mod http;
pub mod loadbalancing;
pub mod net;
#[cfg(feature = "local-redir")]
pub mod redir;
pub mod socks;
#[cfg(feature = "local-tunnel")]
pub mod tunnel;
pub mod utils;

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

    #[cfg(feature = "local-dns")]
    if let Some(ns) = config.local_dns_addr {
        trace!("initializing direct DNS resolver for {}", ns);

        let mut resolver = LocalDnsResolver::new(ns);
        resolver.set_mode(Mode::TcpAndUdp);
        resolver.set_ipv6_first(config.ipv6_first);
        resolver.set_connect_opts(context.connect_opts_ref().clone());
        context.set_dns_resolver(Arc::new(DnsResolver::custom_resolver(resolver)));
    }

    #[cfg(feature = "trust-dns")]
    if matches!(context.dns_resolver(), DnsResolver::System) {
        match DnsResolver::trust_dns_resolver(config.dns, config.ipv6_first).await {
            Ok(r) => {
                context.set_dns_resolver(Arc::new(r));
            }
            Err(err) => {
                warn!(
                    "initialize DNS resolver failed, fallback to system resolver, error: {}",
                    err
                );
            }
        }
    }

    if let Some(acl) = config.acl {
        context.set_acl(acl);
    }

    let client_config = config.local_addr.expect("local server requires local address");

    let context = Arc::new(context);

    match config.local_protocol {
        ProtocolType::Socks => {
            use self::socks::Socks;

            let mut server = Socks::with_context(context, client_config, config.server);
            server.set_mode(config.mode);

            if let Some(c) = config.udp_max_associations {
                server.set_udp_capacity(c);
            }
            if let Some(d) = config.udp_timeout {
                server.set_udp_expiry_duration(d);
            }
            if let Some(b) = config.udp_bind_addr {
                server.set_udp_bind_addr(b);
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
