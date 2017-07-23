//! Relay for TCP server that running on local environment

use super::socks5_local;
use relay::BoxIoFuture;

/// Starts a TCP local server
pub fn run() -> BoxIoFuture<()> {
    socks5_local::run()
}
