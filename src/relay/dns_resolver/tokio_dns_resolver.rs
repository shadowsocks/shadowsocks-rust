use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use log::debug;
use tokio::net::lookup_host;

use crate::context::Context;

/// Perform a DNS resolution
pub async fn resolve(
    context: &Context,
    addr: &str,
    port: u16,
    check_forbidden: bool,
) -> io::Result<impl Iterator<Item = SocketAddr>> {
    let mut vaddr = Vec::new();
    for addr in lookup_host((addr, port)).await? {
        let ip = addr.ip();

        if check_forbidden && context.check_forbidden_ip(&ip) {
            debug!("Resolved {} => {}, which is skipped by forbidden_ip", addr, ip);
            continue;
        }

        vaddr.push(addr);
    }

    if vaddr.is_empty() {
        let err = Error::new(
            ErrorKind::Other,
            format!("resolved {}:{}, but all IPs are filtered", addr, port),
        );
        Err(err)
    } else {
        debug!("Resolved {}:{} => {:?}", addr, port, vaddr);
        Ok(vaddr.into_iter())
    }
}
