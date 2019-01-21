//! Local side

use std::io;

use futures::{stream::futures_unordered, Future, Stream};

use crate::{
    config::Config,
    context::{Context, SharedContext},
    plugin::{launch_plugin, PluginMode},
    relay::{boxed_future, tcprelay::local::run as run_tcp, udprelay::local::run as run_udp},
};

/// Options for Local server
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Enable builtin signal monitor
    pub enable_signal_monitor: bool,
}

/// Relay server running under local environment.
pub fn run_opt(config: Config, opt: Options) -> impl Future<Item = (), Error = io::Error> + Send {
    futures::lazy(move || {
        let mut vf = Vec::new();

        let mut context = Context::new(config);

        if opt.enable_signal_monitor {
            let mon = crate::monitor::monitor_signal();
            vf.push(boxed_future(mon));
        }

        if context.config().mode.enable_udp() {
            // Clone config here, because the config for TCP relay will be modified
            // after plugins started
            let udp_context = SharedContext::new(context.clone());

            // Run UDP relay before starting plugins
            // Because plugins doesn't support UDP relay
            let udp_fut = run_udp(udp_context);
            vf.push(boxed_future(udp_fut));
        }

        // Hold it here, kill all plugins when `tokio::run` is finished
        let plugins = launch_plugin(context.config_mut(), PluginMode::Client).expect("Failed to launch plugins");
        context.set_plugins(plugins);

        let tcp_fut = run_tcp(SharedContext::new(context));

        vf.push(boxed_future(tcp_fut));
        futures_unordered(vf).into_future().then(|res| -> io::Result<()> {
            match res {
                Ok(..) => Ok(()),
                Err((err, ..)) => Err(err),
            }
        })
    })
}

/// Relay server running under local environment.
///
/// ```no_run
/// extern crate tokio;
/// extern crate shadowsocks;
///
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
pub fn run(config: Config) -> impl Future<Item = (), Error = io::Error> + Send {
    run_opt(
        config,
        Options {
            enable_signal_monitor: true,
        },
    )
}
