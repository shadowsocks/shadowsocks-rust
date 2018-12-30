//! Relay for TCP server that running on local environment

use std::io;

use futures::Future;

use super::socks5_local;
use context::SharedContext;

/// Starts a TCP local server
pub fn run(context: SharedContext) -> impl Future<Item = (), Error = io::Error> + Send {
    socks5_local::run(context)
}
