//! Local side

use std::io::{self, ErrorKind};

use futures::{future::select_all, FutureExt};
use log::{debug, error, trace, warn};

#[cfg(feature = "local-flow-stat")]
use crate::context::SharedContext;
use crate::{
    config::{Config, ConfigType},
    context::{Context, ServerState},
    plugin::{PluginMode, Plugins},
    relay::{
        tcprelay::local::run as run_tcp,
        udprelay::local::run as run_udp,
        utils::set_nofile,
    },
};

/// Relay server running under local environment.
pub async fn run(mut config: Config) -> io::Result<()> {
    trace!("initializing local server with {:?}", config);

    assert!(config.config_type.is_local());

    if let Some(nofile) = config.nofile {
        debug!("setting RLIMIT_NOFILE to {}", nofile);
        if let Err(err) = set_nofile(nofile) {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    warn!("insufficient permission to change RLIMIT_NOFILE, try to restart as root user");
                }
                ErrorKind::InvalidInput => {
                    warn!("invalid `nofile` value {}, decrease it and try again", nofile);
                }
                _ => {
                    error!("failed to set RLIMIT_NOFILE with value {}, error: {}", nofile, err);
                }
            }
            return Err(err);
        }
    }

    let config_type = config.config_type;
    let mode = config.mode;

    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new_shared(&config).await;

    let mut vf = Vec::new();

    let enable_tcp = match config_type {
        // Socks5 always true, because UDP associate command also requires a TCP connection
        #[cfg(not(target_os = "android"))]
        ConfigType::Socks5Local => true,
        // On Android, we allows UDP only mode to support fallback UDP upstream
        #[cfg(target_os = "android")]
        ConfigType::Socks5Local => mode.enable_tcp(),

        // Socks4 always true
        #[cfg(feature = "local-socks4")]
        ConfigType::Socks4Local => true,

        // Tunnel mode controlled by this flag
        #[cfg(feature = "local-tunnel")]
        ConfigType::TunnelLocal => mode.enable_tcp(),

        // HTTP must be TCP
        #[cfg(feature = "local-http")]
        ConfigType::HttpLocal => true,

        // HTTPS must be TCP
        #[cfg(all(
            feature = "local-http",
            any(feature = "local-http-native-tls", feature = "local-http-rustls")
        ))]
        ConfigType::HttpsLocal => true,

        // Redir mode controlled by this flag
        #[cfg(feature = "local-redir")]
        ConfigType::RedirLocal => mode.enable_tcp(),

        _ => false,
    };

    let context = if enable_tcp {
        // Run TCP local server if
        //
        //  1. Enabled TCP relay
        //  2. Not in tunnel mode. (Socks5 UDP relay requires TCP port enabled)

        if config.has_server_plugins() {
            let plugins = Plugins::launch_plugins(&mut config, PluginMode::Client).await?;
            vf.push(plugins.join_all().boxed());
        }

        let context = Context::new_with_state_shared(config, state);

        let tcp_fut = run_tcp(context.clone());
        vf.push(tcp_fut.boxed());

        context
    } else {
        Context::new_with_state_shared(config, state)
    };

    let enable_udp = match config_type {
        ConfigType::Socks5Local => mode.enable_udp(),
        #[cfg(feature = "local-tunnel")]
        ConfigType::TunnelLocal => mode.enable_udp(),
        #[cfg(feature = "local-redir")]
        ConfigType::RedirLocal => mode.enable_udp(),
        _ => false,
    };

    if enable_udp {
        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(context.clone());
        vf.push(udp_fut.boxed());
    }

    #[cfg(feature = "local-dns")]
    if context.config().is_local_dns_relay() {
        use crate::relay::dnsrelay::run as run_dns;

        // DNS relay local server
        let dns_relay = run_dns(context.clone());
        vf.push(dns_relay.boxed());
    }

    #[cfg(feature = "local-flow-stat")]
    if context.config().stat_path.is_some() {
        // For Android's flow statistic

        let report_fut = flow_report_task(context.clone());
        vf.push(report_fut.boxed());
    }

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("one of servers exited unexpectly, result: {:?}", res);

    // Tells all detached tasks to exit
    context.set_server_stopped();

    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}

#[cfg(feature = "local-flow-stat")]
async fn flow_report_task(context: SharedContext) -> io::Result<()> {
    use std::{slice, time::Duration};

    use tokio::{io::AsyncWriteExt, net::UnixStream, time};

    // Android's flow statistic report RPC
    let path = context.config().stat_path.as_ref().expect("stat_path must be provided");
    let timeout = Duration::from_secs(1);

    while context.server_running() {
        // keep it as libev's default, 0.5 seconds
        time::sleep(Duration::from_millis(500)).await;
        let mut stream = match time::timeout(timeout, UnixStream::connect(path)).await {
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

        let flow_stat = context.local_flow_statistic();
        let tx = flow_stat.tcp().tx() + flow_stat.udp().tx();
        let rx = flow_stat.tcp().rx() + flow_stat.udp().rx();

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
    Ok(())
}
