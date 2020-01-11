//! Local side

use std::io;

use futures::{future::select_all, FutureExt};
use log::{error, trace};
use tokio::runtime::Handle;

use crate::{
    config::{Config, ConfigType},
    context::{Context, ServerState},
    plugin::{PluginMode, Plugins},
    relay::{tcprelay::local::run as run_tcp, udprelay::local::run as run_udp},
};

/// Relay server running under local environment.
pub async fn run(mut config: Config, rt: Handle) -> io::Result<()> {
    trace!("{:?}", config);
    assert!(config.config_type != ConfigType::Server);

    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new(&config, rt).await?;

    let mut vf = Vec::new();

    let enable_udp = match config.config_type {
        ConfigType::Socks5Local | ConfigType::TunnelLocal => config.mode.enable_udp(),
        _ => false,
    };

    if enable_udp {
        // Clone config here, because the config for TCP relay will be modified
        // after plugins started.
        // But DNS resolver and running state flag is still shared.
        let udp_context = Context::new_shared(config.clone(), state.clone());

        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(udp_context);
        vf.push(udp_fut.boxed());
    }

    let enable_tcp = match config.config_type {
        // Socks5 always true, because UDP associate command also requires a TCP connection
        ConfigType::Socks5Local => true,
        // Only tunnel mode controlled by this flag
        ConfigType::TunnelLocal => config.mode.enable_tcp(),
        // HTTP must be TCP
        ConfigType::HttpLocal => true,

        _ => false,
    };

    if enable_tcp {
        // Run TCP local server if
        //
        //  1. Enabled TCP relay
        //  2. Not in tunnel mode. (Socks5 UDP relay requires TCP port enabled)

        if config.has_server_plugins() {
            let plugins = Plugins::launch_plugins(&mut config, PluginMode::Client)?;
            vf.push(plugins.into_future().boxed());
        }

        let tcp_fut = run_tcp(Context::new_shared(config, state.clone()));
        vf.push(tcp_fut.boxed());
    }

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("one of servers exited unexpectly, result: {:?}", res);

    // Tells all detached tasks to exit
    state.server_stopped();

    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}
