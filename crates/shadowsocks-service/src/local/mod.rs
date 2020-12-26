//! Shadowsocks Local Server

#[cfg(feature = "local-flow-stat")]
use std::path::PathBuf;
use std::{io, sync::Arc, time::Duration};

use futures::{future, FutureExt};
use log::{error, trace, warn};
#[cfg(any(feature = "local-dns", feature = "trust-dns"))]
use shadowsocks::dns_resolver::DnsResolver;
use shadowsocks::{
    net::{AcceptOpts, ConnectOpts},
    plugin::{Plugin, PluginMode},
};

use crate::config::{Config, ConfigType, ProtocolType};
#[cfg(feature = "local-flow-stat")]
use crate::net::FlowStat;

use self::{
    context::ServiceContext,
    loadbalancing::{PingBalancerBuilder, ServerIdent},
};

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

/// Starts a shadowsocks local server
pub async fn run(mut config: Config) -> io::Result<()> {
    assert!(config.config_type == ConfigType::Local && config.local_addr.is_some());
    assert!(config.server.len() > 0);

    trace!("{:?}", config);

    #[cfg(unix)]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    let mut context = ServiceContext::new();

    let mut connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        #[cfg(any(target_os = "linux", target_os = "android"))]
        bind_interface: config.outbound_bind_interface,

        ..Default::default()
    };
    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    context.set_connect_opts(connect_opts);

    let mut accept_opts = AcceptOpts::default();
    accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
    accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
    accept_opts.tcp.nodelay = config.no_delay;

    #[cfg(all(feature = "local-dns", feature = "trust-dns"))]
    if let Some(socket_addr) = config.local_dns_addr {
        use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig};

        trace!("initializing direct DNS resolver for {}", socket_addr);

        let mut resolver_config = ResolverConfig::new();

        resolver_config.add_name_server(NameServerConfig {
            socket_addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-tls")]
            tls_config: None,
        });
        resolver_config.add_name_server(NameServerConfig {
            socket_addr,
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_nx_responses: false,
            #[cfg(feature = "dns-over-tls")]
            tls_config: None,
        });

        match DnsResolver::trust_dns_resolver(Some(resolver_config), config.ipv6_first).await {
            Ok(r) => {
                context.set_dns_resolver(Arc::new(r));
            }
            Err(err) => {
                error!(
                    "initialize DNS resolver failed, nameserver: {}, error: {}",
                    socket_addr, err
                );
                return Err(err);
            }
        }
    }

    #[cfg(feature = "trust-dns")]
    if context.dns_resolver().is_system_resolver() {
        if config.dns.is_some() || crate::hint_support_default_system_resolver() {
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
    }

    if let Some(acl) = config.acl {
        context.set_acl(acl);
    }

    let client_config = config.local_addr.expect("local server requires local address");

    let context = Arc::new(context);

    let mut vfut = Vec::new();

    let enable_tcp = match config.local_protocol {
        ProtocolType::Socks => config.mode.enable_tcp(),
        #[cfg(feature = "local-tunnel")]
        ProtocolType::Tunnel => config.mode.enable_tcp(),
        #[cfg(feature = "local-http")]
        ProtocolType::Http => true,
        #[cfg(feature = "local-redir")]
        ProtocolType::Redir => config.mode.enable_tcp(),
        #[cfg(feature = "local-dns")]
        ProtocolType::Dns => config.mode.enable_tcp(),
    };

    if enable_tcp {
        // Start plugins for TCP proxies

        let mut plugins = Vec::with_capacity(config.server.len());

        for server in &mut config.server {
            if let Some(c) = server.plugin() {
                let plugin = Plugin::start(c, server.addr(), PluginMode::Client)?;
                server.set_plugin_addr(plugin.local_addr().into());
                plugins.push(plugin);
            }
        }

        // Load balancer will check all servers' score before server's actual start.
        // So we have to ensure all plugins have been started before that.
        if config.server.len() > 1 && !plugins.is_empty() {
            let mut check_fut = Vec::with_capacity(plugins.len());

            for plugin in &plugins {
                // 3 seconds is not a carefully selected value
                // I choose that because any values bigger will make me fell too long.
                check_fut.push(plugin.wait_started(Duration::from_secs(3)));
            }

            // Run all of them simutaneously
            let _ = future::join_all(check_fut).await;
        }

        // Join all of them
        for plugin in plugins {
            vfut.push(
                async move {
                    match plugin.join().await {
                        Ok(status) => {
                            error!("plugin exited with status: {}", status);
                            Ok(())
                        }
                        Err(err) => {
                            error!("plugin exited with error: {}", err);
                            Err(err)
                        }
                    }
                }
                .boxed(),
            );
        }
    }

    // Create a service balancer for choosing between multiple servers
    //
    // XXX: This have to be called after allocating plugins' addresses
    let balancer = {
        let mut balancer_builder = PingBalancerBuilder::new(context.clone(), config.mode);
        for server in config.server {
            balancer_builder.add_server(ServerIdent::new(server));
        }
        let (balancer, checker) = balancer_builder.build().await;
        tokio::spawn(checker);

        balancer
    };

    #[cfg(feature = "local-dns")]
    if matches!(config.local_protocol, ProtocolType::Dns) || config.dns_bind_addr.is_some() {
        use self::dns::Dns;

        let local_addr = config.local_dns_addr.expect("missing local_dns_addr");
        let remote_addr = config.remote_dns_addr.expect("missing remote_dns_addr");

        let bind_addr = config.dns_bind_addr.as_ref().unwrap_or_else(|| &client_config);

        let mut server = Dns::with_context(context.clone(), local_addr, remote_addr);
        server.set_mode(config.mode);

        vfut.push(server.run(bind_addr, balancer.clone()).boxed());
    }

    #[cfg(feature = "local-flow-stat")]
    if let Some(stat_path) = config.stat_path {
        // For Android's flow statistic

        let report_fut = flow_report_task(stat_path, context.flow_stat());
        vfut.push(report_fut.boxed());
    }

    match config.local_protocol {
        ProtocolType::Socks => {
            use self::socks::Socks;

            let mut server = Socks::with_context(context);
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

            vfut.push(server.run(&client_config, balancer).boxed());
        }
        #[cfg(feature = "local-tunnel")]
        ProtocolType::Tunnel => {
            use self::tunnel::Tunnel;

            let forward_addr = config.forward.expect("tunnel requires forward address");

            let mut server = Tunnel::with_context(context, forward_addr);

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

            vfut.push(server.run(&client_config, balancer).boxed());
        }
        #[cfg(feature = "local-http")]
        ProtocolType::Http => {
            use self::http::Http;

            let server = Http::with_context(context);
            vfut.push(server.run(&client_config, balancer).boxed());
        }
        #[cfg(feature = "local-redir")]
        ProtocolType::Redir => {
            use self::redir::Redir;

            let mut server = Redir::with_context(context);
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

            vfut.push(server.run(&client_config, balancer).boxed());
        }
        #[cfg(feature = "local-dns")]
        ProtocolType::Dns => {}
    }

    let (res, ..) = future::select_all(vfut).await;
    res
}

#[cfg(feature = "local-flow-stat")]
async fn flow_report_task(stat_path: PathBuf, flow_stat: Arc<FlowStat>) -> io::Result<()> {
    use std::slice;

    use log::debug;
    use tokio::{io::AsyncWriteExt, net::UnixStream, time};

    // Android's flow statistic report RPC
    let timeout = Duration::from_secs(1);

    loop {
        // keep it as libev's default, 0.5 seconds
        time::sleep(Duration::from_millis(500)).await;
        let mut stream = match time::timeout(timeout, UnixStream::connect(&stat_path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                debug!("send client flow statistic error: {}", err);
                continue;
            }
            Err(..) => {
                debug!("send client flow statistic error: timeout");
                continue;
            }
        };

        let tx = flow_stat.tx();
        let rx = flow_stat.rx();

        let buf: [u64; 2] = [tx as u64, rx as u64];
        let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

        match time::timeout(timeout, stream.write_all(buf)).await {
            Ok(Ok(..)) => {}
            Ok(Err(err)) => {
                debug!("send client flow statistic error: {}", err);
            }
            Err(..) => {
                debug!("send client flow statistic error: timeout");
            }
        }
    }
}
