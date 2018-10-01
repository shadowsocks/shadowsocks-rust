//! Relay for TCP server that running on local environment

use std::{io, sync::Arc};

use futures::Future;

use super::socks5_local;
use config::Config;

/// Starts a TCP local server
pub fn run(config: Arc<Config>) -> impl Future<Item = (), Error = io::Error> + Send {
    socks5_local::run(config)
}
