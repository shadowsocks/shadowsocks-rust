//! DNS relay

use std::io;

use futures::{self, Future};

use crate::{
    config::Config,
    context::{Context, SharedContext},
    relay::udprelay::dns::run as run_udp,
};

/// DNS Relay server running under local environment.
pub fn run(config: Config) -> impl Future<Item = (), Error = io::Error> + Send {
    futures::lazy(move || run_udp(SharedContext::new(Context::new_dns(config))))
}
