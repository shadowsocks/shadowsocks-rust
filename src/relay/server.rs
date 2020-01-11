//! Server side

use std::io;

use futures::future::{select_all, FutureExt};
use log::{error, trace};
use tokio::runtime::Handle;

use crate::{
    config::{Config, ConfigType},
    context::{Context, ServerState},
    plugin::{PluginMode, Plugins},
    relay::{tcprelay::server::run as run_tcp, udprelay::server::run as run_udp},
};

/// Relay server running on server side.
pub async fn run(mut config: Config, rt: Handle) -> io::Result<()> {
    trace!("{:?}", config);
    assert!(config.config_type == ConfigType::Server);

    // Create a context containing a DNS resolver and server running state flag.
    let state = ServerState::new(&config, rt).await?;

    let mut vf = Vec::new();

    if config.mode.enable_udp() {
        // Clone config here, because the config for TCP relay will be modified
        // after plugins started
        let udp_context = Context::new_shared(config.clone(), state.clone());

        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(udp_context);
        vf.push(udp_fut.boxed());
    }

    if config.mode.enable_tcp() {
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
