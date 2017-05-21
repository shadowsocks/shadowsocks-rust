//! Relay for TCP server that running on local environment

use relay::BoxIoFuture;
use super::socks5_local;

/// Starts a TCP local server
pub fn run() -> BoxIoFuture<()> {
    socks5_local::run()
}
