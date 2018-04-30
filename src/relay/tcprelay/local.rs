//! Relay for TCP server that running on local environment

use std::sync::Arc;

use tokio_io::IoFuture;

use super::socks5_local;
use config::Config;

/// Starts a TCP local server
pub fn run(config: Arc<Config>) -> IoFuture<()> {
    socks5_local::run(config)
}
