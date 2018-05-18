//! DNS relay

use std::io;
use std::sync::Arc;

use futures::Future;

use config::Config;
use relay::udprelay::dns::run as run_udp;

/// DNS Relay server running under local environment.
pub fn run(config: Config) -> impl Future<Item = (), Error = io::Error> + Send {
    let config = Arc::new(config);
    run_udp(config)
}
