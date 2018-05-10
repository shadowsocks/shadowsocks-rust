//! DNS relay

use std::sync::Arc;

use futures::Future;
use tokio;

use config::Config;
use relay::udprelay::dns::run as run_udp;

/// DNS Relay server running under local environment.
pub fn run(config: Config) {
    let config = Arc::new(config);
    tokio::run(run_udp(config).then(|res| match res {
                                        Ok(..) => Ok(()),
                                        Err(err) => panic!("Failed to run server, err: {}", err),
                                    }));
}
