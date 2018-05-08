//! Server side

use std::sync::Arc;

use tokio;

use futures::future::join_all;
use futures::Future;

use config::Config;
use plugin::{launch_plugin, PluginMode};
use relay::tcprelay::server::run as run_tcp;
use relay::udprelay::server::run as run_udp;

/// Relay server running on server side.
///
/// ```no_run
/// use shadowsocks::config::{Config, ServerConfig};
/// use shadowsocks::crypto::CipherType;
/// use shadowsocks::relay::server::run;
///
/// let mut config = Config::new();
/// config.server = vec![ServerConfig::basic("127.0.0.1:8388".parse().unwrap(),
///                                          "server-password".to_string(),
///                                          CipherType::Aes256Cfb)];
/// run(config);
/// ```
///
pub fn run(mut config: Config) {
    // Hold it here, kill all plugins when Core is finished
    let plugins = launch_plugin(&mut config, PluginMode::Server).expect("Failed to launch plugins");
    let mon = ::monitor::monitor_signal(plugins);

    let config = Arc::new(config);
    let enable_udp = config.enable_udp;

    if enable_udp {
        let tcp_fut = run_tcp(config.clone());
        let udp_fut = run_udp(config);
        tokio::run(join_all(vec![mon, tcp_fut, udp_fut]).then(|res| match res {
                                                                  Ok(..) => Ok(()),
                                                                  Err(err) => {
                                                                      panic!("Failed to run server, err: {}", err)
                                                                  }
                                                              }));
    } else {
        let tcp_fut = run_tcp(config);
        tokio::run(join_all(vec![mon, tcp_fut]).then(|res| match res {
                                                         Ok(..) => Ok(()),
                                                         Err(err) => panic!("Failed to run server, err: {}", err),
                                                     }))
    }
}
