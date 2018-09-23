//! DNS relay

use std::io;
use std::sync::Arc;

use futures::Future;

use super::dns_resolver::set_dns_config;
use config::Config;
use relay::udprelay::dns::run as run_udp;

/// DNS Relay server running under local environment.
pub fn run(config: Config) -> impl Future<Item = (), Error = io::Error> + Send {
    if let Some(c) = config.get_dns_config() {
        set_dns_config(c);
    }

    let config = Arc::new(config);
    run_udp(config)
}
