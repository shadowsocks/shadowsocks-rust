//! Local side

use std::io;

use tokio_core::reactor::Core;

use futures::Future;

use config::Config;
use plugin::{PluginMode, launch_plugin};
use relay::Context;
use relay::tcprelay::local::run as run_tcp;
use relay::udprelay::local::run as run_udp;

/// Relay server running under local environment.
///
/// ```no_run
/// use shadowsocks::relay::local::run;
/// use shadowsocks::config::{Config, ServerConfig};
/// use shadowsocks::crypto::CipherType;
///
/// let mut config = Config::new();
/// config.local = Some("127.0.0.1:1080".parse().unwrap());
/// config.server = vec![
///     ServerConfig::basic("127.0.0.1:8388".parse().unwrap(),
///                         "server-password".to_string(),
///                         CipherType::Aes256Cfb)];
/// run(config).unwrap();
/// ```
pub fn run(mut config: Config) -> io::Result<()> {
    let mut lp = Core::new()?;
    let handle = lp.handle();

    let enable_udp = config.enable_udp;

    // Hold it here, kill all plugins when Core is finished
    let _plugins = launch_plugin(&mut config, PluginMode::Client)?;
    ::monitor::monitor_signal(&handle);

    let context = Context::new(handle, config);
    Context::set(&context, move || if enable_udp {
        let tcp_fut = run_tcp();
        let udp_fut = run_udp();
        lp.run(tcp_fut.join(udp_fut).map(|_| ()))
    } else {
        let tcp_fut = run_tcp();
        lp.run(tcp_fut)
    })
}
