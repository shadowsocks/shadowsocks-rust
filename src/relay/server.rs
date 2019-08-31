//! Server side

use std::{io, pin::Pin};

use futures::{
    future::{pending, select_all},
    select,
    Future,
    FutureExt,
};

use log::error;

use crate::{
    config::Config,
    context::{Context, SharedContext},
    plugin::{launch_plugins, PluginMode},
    relay::tcprelay::server::run as run_tcp,
};

/// Relay server running on server side.
///
/// ```no_run
/// use shadowsocks::{
///     config::{Config, ConfigType, ServerConfig},
///     crypto::CipherType,
///     relay::server::run,
/// };
///
/// use tokio::prelude::*;
///
/// let mut config = Config::new(ConfigType::Server);
/// config.server = vec![ServerConfig::basic(
///     "127.0.0.1:8388".parse().unwrap(),
///     "server-password".to_string(),
///     CipherType::Aes256Cfb,
/// )];
///
/// let fut = run(config);
/// tokio::run(fut.map_err(|err| panic!("Server run failed with error {}", err)));
/// ```
pub async fn run(config: Config) -> io::Result<()> {
    let mut context = Context::new(config);

    let mut vf = Vec::new();

    // let udp_fut = if context.config().mode.enable_udp() {
    //     // Clone config here, because the config for TCP relay will be modified
    //     // after plugins started
    //     let udp_context = SharedContext::new(context.clone());

    //     // Run UDP relay before starting plugins
    //     // Because plugins doesn't support UDP relay
    //     run_udp(udp_context)
    // } else {
    //     pending::<io::Result<()>>()
    // };

    if context.config().mode.enable_tcp() {
        if context.config().has_server_plugins() {
            let plugins = launch_plugins(context.config_mut(), PluginMode::Client);
            vf.push(Box::pin(plugins) as Pin<Box<dyn Future<Output = io::Result<()>> + Send>>);
        }

        let tcp_fut = run_tcp(SharedContext::new(context));
        vf.push(Box::pin(tcp_fut) as Pin<Box<dyn Future<Output = io::Result<()>> + Send>>);
    }

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("One of TCP servers exited unexpectly, result: {:?}", res);
    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}
