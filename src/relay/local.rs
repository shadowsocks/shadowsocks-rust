//! Local side

use std::io;

use futures::{future::select_all, FutureExt};

use log::error;

use crate::{
    config::Config,
    context::{Context, SharedContext},
    plugin::{PluginMode, Plugins},
    relay::tcprelay::local::run as run_tcp,
};

/// Relay server running under local environment.
///
/// ```no_run
/// use shadowsocks::{
///     config::{Config, ConfigType, ServerConfig},
///     crypto::CipherType,
///     relay::local::run,
/// };
///
/// use tokio::prelude::*;
///
/// let mut config = Config::new(ConfigType::Local);
/// config.local = Some("127.0.0.1:1080".parse().unwrap());
/// config.server = vec![ServerConfig::basic(
///     "127.0.0.1:8388".parse().unwrap(),
///     "server-password".to_string(),
///     CipherType::Aes256Cfb,
/// )];
/// let fut = run(config);
/// tokio::run(fut.map_err(|err| panic!("Server run failed with error {}", err)));
/// ```
pub async fn run(config: Config) -> io::Result<()> {
    let mut context = Context::new(config);

    let mut vf = Vec::new();

    // if context.config().mode.enable_udp() {
    //     // Clone config here, because the config for TCP relay will be modified
    //     // after plugins started
    //     let udp_context = SharedContext::new(context.clone());

    //     // Run UDP relay before starting plugins
    //     // Because plugins doesn't support UDP relay
    //     let udp_fut = run_udp(udp_context);
    //     vf.push(Box::pin(udp_fut) as BoxFuture<io::Result<()>>);
    // }

    if context.config().has_server_plugins() {
        let plugins = Plugins::launch_plugins(context.config_mut(), PluginMode::Client)?;
        vf.push(plugins.into_future().boxed());
    }

    let tcp_fut = run_tcp(SharedContext::new(context));
    vf.push(tcp_fut.boxed());

    let (res, ..) = select_all(vf.into_iter()).await;
    error!("One of TCP servers exited unexpectly, result: {:?}", res);
    Err(io::Error::new(io::ErrorKind::Other, "server exited unexpectly"))
}
