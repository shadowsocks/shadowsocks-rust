use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use tokio::net::lookup_host;

use crate::context::Context;

/// Perform a DNS resolution
pub async fn resolve(_: &Context, addr: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    match lookup_host((addr, port)).await {
        Ok(v) => Ok(v.collect()),
        Err(err) => {
            let err = Error::new(
                ErrorKind::Other,
                format!("dns resolve {}:{} error: {}", addr, port, err),
            );
            Err(err)
        }
    }
}
