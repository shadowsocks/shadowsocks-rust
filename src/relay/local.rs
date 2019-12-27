//! Local side

use std::io;

use futures::{future::select_all, FutureExt};
use log::{error, trace};
use tokio::runtime::Handle;

use crate::{
    config::Config,
    context::{Context, SharedServerState},
    plugin::{PluginMode, Plugins},
    relay::{tcprelay::local::run as run_tcp, udprelay::local::run as run_udp},
};

/// Relay server running under local environment.
pub async fn run(mut config: Config, rt: Handle) -> io::Result<()> {
    trace!("{:?}", config);

    // Create a context containing a DNS resolver and server running state flag.
    let state = SharedServerState::new(&config, rt).await?;

    let mut vf = Vec::new();

    if config.mode.enable_udp() {
        // Clone config here, because the config for TCP relay will be modified
        // after plugins started.
        // But DNS resolver and running state flag is still shared.
        let udp_context = Context::new_shared(config.clone(), state.clone());

        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(udp_context);
        vf.push(udp_fut.boxed());
    }

    if config.mode.enable_tcp() || config.forward.is_none() {
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
