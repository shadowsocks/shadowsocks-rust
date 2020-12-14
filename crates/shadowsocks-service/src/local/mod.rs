//! Shadowsocks Local Server

use std::{io, sync::Arc};

use log::trace;
#[cfg(feature = "trust-dns")]
use shadowsocks::dns_resolver::create_resolver;
use shadowsocks::net::ConnectOpts;

use crate::config::{Config, ConfigType, ProtocolType};

pub mod acl;
pub mod context;
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

    let connect_opts = Arc::new(ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        ..Default::default()
    });

    #[cfg(feature = "trust-dns")]
    let resolver = Arc::new(create_resolver(config.dns, config.ipv6_first).await?);

    let client_config = config.local_addr.expect("local server requires local address");
    let acl = config.acl.map(Arc::new);

    match config.local_protocol {
        ProtocolType::Socks => {
            use self::socks::Socks;

            let mut server = Socks::new(client_config, config.server);

            #[cfg(feature = "trust-dns")]
            server.set_dns_resolver(resolver);

            server.set_connect_opts(connect_opts);
            if let Some(c) = config.udp_max_associations {
                server.set_udp_capacity(c);
            }
            if let Some(d) = config.udp_timeout {
                server.set_udp_expiry_duration(d);
            }
            if config.no_delay {
                server.set_nodelay(true);
            }
            if let Some(acl) = acl {
                server.set_acl(acl);
            }

            server.run().await
        }
        #[cfg(feature = "local-tunnel")]
        ProtocolType::Tunnel => {
            use self::tunnel::Tunnel;

            let forward_addr = config.forward.expect("tunnel requires forward address");

            let mut server = Tunnel::new(client_config, config.server, forward_addr);

            #[cfg(feature = "trust-dns")]
            server.set_dns_resolver(resolver);

            server.set_connect_opts(connect_opts);
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
        ProtocolType::Http | ProtocolType::Https => {
            use self::http::Http;

            let mut server = Http::new(client_config, config.server);

            #[cfg(feature = "trust-dns")]
            server.set_dns_resolver(resolver);

            server.set_connect_opts(connect_opts);

            server.run().await
        }
        #[cfg(feature = "local-dns")]
        ProtocolType::Dns => unimplemented!(),
    }
}
