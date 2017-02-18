//! Local side

use std::rc::Rc;
use std::io;

use tokio_core::reactor::Core;

use futures::Future;

use relay::tcprelay::local::run as run_tcp;
use relay::udprelay::local::run as run_udp;
use config::Config;

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
pub fn run(config: Config) -> io::Result<()> {
    let mut lp = try!(Core::new());
    let handle = lp.handle();
    let config = Rc::new(config);

    let tcp_fut = run_tcp(config.clone(), handle.clone());

    if config.enable_udp {
        lp.run(tcp_fut.join(run_udp(config, handle)).map(|_| ()))
    } else {
        lp.run(tcp_fut)
    }
}
