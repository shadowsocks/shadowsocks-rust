use std::io;

use crate::context::SharedContext;

/// Starts a UDP local server
pub async fn run(_: SharedContext) -> io::Result<()> {
    unimplemented!("UDP Transparent Proxy (redir) isn't implemented yet");
}
