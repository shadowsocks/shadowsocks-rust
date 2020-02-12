use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use log::debug;
use tokio::net::lookup_host;

use crate::context::Context;

/// Perform a DNS resolution
pub async fn resolve(context: &Context, addr: &str, port: u16, check_forbidden: bool) -> io::Result<Vec<SocketAddr>> {
    match lookup_host((addr, port)).await {
        Err(err) => {
            let err = Error::new(ErrorKind::Other, format!("dns resolve {}:{}, {}", addr, port, err));
            Err(err)
        }
        Ok(addrs) => {
            let mut vaddr = Vec::new();
            for addr in addrs {
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
                Ok(vaddr)
            }
        }
    }
}
