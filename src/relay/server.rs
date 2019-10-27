//! Server side

use std::io;

use futures::future::{select_all, FutureExt};

use log::error;

use crate::{
    config::Config,
    context::{Context, SharedContext},
    plugin::{PluginMode, Plugins},
    relay::{tcprelay::server::run as run_tcp, udprelay::server::run as run_udp},
};

/// Relay server running on server side.
pub async fn run(config: Config) -> io::Result<()> {
    let mut context = Context::new(config);

    let mut vf = Vec::new();

    if context.config().mode.enable_udp() {
        // Clone config here, because the config for TCP relay will be modified
        // after plugins started
        let udp_context = SharedContext::new(context.clone());

        // Run UDP relay before starting plugins
        // Because plugins doesn't support UDP relay
        let udp_fut = run_udp(udp_context);
        vf.push(udp_fut.boxed());
    }

    if context.config().mode.enable_tcp() {
        if context.config().has_server_plugins() {
            let plugins = Plugins::launch_plugins(context.config_mut(), PluginMode::Client)?;
            vf.push(plugins.into_future().boxed());
        }

        let tcp_fut = run_tcp(SharedContext::new(context));
        vf.push(tcp_fut.boxed());
    }

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("One of TCP servers exited unexpectly, result: {:?}", res);
    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}
