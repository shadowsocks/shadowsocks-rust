//! Local side

use std::sync::Arc;

use tokio;

use futures::future::join_all;
use futures::Future;

use config::Config;
use plugin::{launch_plugin, PluginMode};
use relay::boxed_future;
use relay::tcprelay::local::run as run_tcp;
use relay::udprelay::local::run as run_udp;

/// Relay server running under local environment.
///
/// ```no_run
/// use shadowsocks::config::{Config, ServerConfig};
/// use shadowsocks::crypto::CipherType;
/// use shadowsocks::relay::local::run;
///
/// let mut config = Config::new();
/// config.local = Some("127.0.0.1:1080".parse().unwrap());
/// config.server = vec![ServerConfig::basic("127.0.0.1:8388".parse().unwrap(),
///                                          "server-password".to_string(),
///                                          CipherType::Aes256Cfb)];
/// run(config);
/// ```
pub fn run(mut config: Config) {
    // Hold it here, kill all plugins when Core is finished
    let plugins = launch_plugin(&mut config, PluginMode::Client).expect("Failed to launch plugins");
    let mon = ::monitor::monitor_signal(plugins);

    let config = Arc::new(config);

    let enable_udp = config.enable_udp;

    let tcp_fut = run_tcp(config.clone());
    let mut vf = vec![boxed_future(mon), boxed_future(tcp_fut)];
    if enable_udp {
        let udp_fut = run_udp(config);
        vf.push(boxed_future(udp_fut));
    }

    tokio::run(join_all(vf).then(|res| match res {
                                     Ok(..) => Ok(()),
                                     Err(err) => panic!("Failed to run server, err: {}", err),
                                 }));
}
