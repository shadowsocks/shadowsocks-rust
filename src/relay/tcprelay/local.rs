//! Relay for TCP server that running on local environment

use std::io;

use super::socks5_local;
use crate::context::SharedContext;

/// Starts a TCP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    socks5_local::run(context).await
}
