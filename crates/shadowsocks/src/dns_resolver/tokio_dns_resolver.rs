use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};

use log::{trace, warn};
use tokio::net::lookup_host;

use crate::context::Context;

/// Perform a DNS resolution
pub async fn resolve<'a>(_: &Context, addr: &'a str, port: u16) -> io::Result<impl Iterator<Item = SocketAddr> + 'a> {
    static TOKIO_USED: AtomicBool = AtomicBool::new(false);
    if !TOKIO_USED.swap(true, Ordering::Relaxed) {
        warn!("Tokio resolver is used. Performance might deteriorate.");
    }

    if cfg!(not(feature = "trust-dns")) {
        trace!("DNS resolving {}:{} with tokio", addr, port);
    }

    match lookup_host((addr, port)).await {
        Ok(v) => Ok(v),
        Err(err) => {
            let err = Error::new(
                ErrorKind::Other,
                format!("dns resolve {}:{} error: {}", addr, port, err),
            );
            Err(err)
        }
    }
}
