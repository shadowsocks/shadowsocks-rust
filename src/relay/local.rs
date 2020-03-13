//! Local side

use std::io::{self, ErrorKind};

use futures::{future::select_all, FutureExt};
use log::{debug, error, trace, warn};
use tokio::runtime::Handle;

use crate::{
    config::{Config, ConfigType},
    context::{Context, ServerState, SharedContext},
    plugin::{PluginMode, Plugins},
    relay::{tcprelay::local::run as run_tcp, udprelay::local::run as run_udp, utils::set_nofile},
};

#[cfg(target_os = "android")]
use crate::relay::dnsrelay::run as run_dns_relay;

/// Relay server running under local environment.
pub async fn run(mut config: Config, rt: Handle) -> io::Result<()> {
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
    let state = ServerState::new_shared(&config, rt).await;

    let mut vf = Vec::new();

    let enable_tcp = match config_type {
        // Socks5 always true, because UDP associate command also requires a TCP connection
        ConfigType::Socks5Local => true,
        // Tunnel mode controlled by this flag
        ConfigType::TunnelLocal => mode.enable_tcp(),
        // HTTP must be TCP
        ConfigType::HttpLocal => true,
        // Redir mode controlled by this flag
        ConfigType::RedirLocal => mode.enable_tcp(),

        _ => false,
    };

    let context = if enable_tcp {
        // Run TCP local server if
        //
        //  1. Enabled TCP relay
        //  2. Not in tunnel mode. (Socks5 UDP relay requires TCP port enabled)

        if config.has_server_plugins() {
            let plugins = Plugins::launch_plugins(&mut config, PluginMode::Client)?;

            // Wait until all plugins actually start
            // Some plugins require quite a lot bootstrap time
            Plugins::check_plugins_started(&config).await?;

            vf.push(plugins.into_future().boxed());
        }

        let context = Context::new_shared(config, state);

        let tcp_fut = run_tcp(context.clone());
        vf.push(tcp_fut.boxed());

        context
    } else {
        Context::new_shared(config, state)
    };

    let enable_udp = match config_type {
        ConfigType::Socks5Local | ConfigType::TunnelLocal | ConfigType::RedirLocal => mode.enable_udp(),
        _ => false,
    };

    if enable_udp {
        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(context.clone());
        vf.push(udp_fut.boxed());
    }

    #[cfg(target_os = "android")]
    {
        // For Android's local resolver
        let dns_relay = run_dns_relay(context.clone());
        vf.push(dns_relay.boxed());
    }

    if cfg!(target_os = "android") && context.config().stat_path.is_some() {
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

#[cfg(target_os = "android")]
async fn flow_report_task(context: SharedContext) -> io::Result<()> {
    use std::{slice, time::Duration};

    use tokio::{io::AsyncWriteExt, net::UnixStream, time};

    // Android's flow statistic report RPC
    let path = context.config().stat_path.as_ref().expect("stat_path must be provided");
    let timeout = Duration::from_secs(1);

    while context.server_running() {
        // keep it as libev's default, 0.5 seconds
        time::delay_for(Duration::from_millis(500)).await;
        let mut stream = match time::timeout(timeout, UnixStream::connect(path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                error!("send client flow statistic error: {}", err);
                continue;
            }
            Err(..) => {
                error!("send client flow statistic error: timeout");
                continue;
            }
        };

        let flow_stat = context.local_flow_statistic();
        let tx = flow_stat.tcp().tx() + flow_stat.udp().tx();
        let rx = flow_stat.tcp().rx() + flow_stat.udp().rx();

        // first is rx, second is tx.
        let buf: [u64; 2] = [rx, tx];
        let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

        match time::timeout(timeout, stream.write_all(buf)).await {
            Ok(Ok(..)) => {}
            Ok(Err(err)) => {
                error!("send client flow statistic error: {}", err);
            }
            Err(..) => {
                error!("send client flow statistic error: timeout");
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
async fn flow_report_task(_context: SharedContext) -> io::Result<()> {
    unimplemented!("only for android")
}
