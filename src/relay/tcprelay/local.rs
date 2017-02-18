//! Relay for TCP server that running on local environment

use std::rc::Rc;

use tokio_core::reactor::Handle;

use config::Config;

use relay::{BoxIoFuture, boxed_future};

use super::socks5_local;

/// Starts a TCP local server
pub fn run(config: Rc<Config>, handle: Handle) -> BoxIoFuture<()> {
    let tcp_fut = socks5_local::run(config.clone(), handle.clone());
    boxed_future(tcp_fut)
}
