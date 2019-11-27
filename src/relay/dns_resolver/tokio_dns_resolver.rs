use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use log::{debug, error};
use tokio::task::spawn_blocking;

use crate::context::SharedContext;

/// Resolve address to IP
pub async fn resolve(
    context: SharedContext,
    addr: &str,
    port: u16,
    check_forbidden: bool,
) -> io::Result<Vec<SocketAddr>> {
    // let addr = addr.to_owned();
    // spawn_blocking(move || {
    //     let mut vaddr = Vec::new();
    //     for addr in (addr.as_str(), port).to_socket_addrs()? {
    //         let ip = addr.ip();

    //         if check_forbidden {
    //             let forbidden_ip = &context.config().forbidden_ip;
    //             if forbidden_ip.contains(&ip) {
    //                 debug!("Resolved {} => {}, which is skipped by forbidden_ip", addr, ip);
    //                 continue;
    //             }
    //         }
    //         vaddr.push(addr);
    //     }

    //     if vaddr.is_empty() {
    //         error!("Failed to resolve {}:{}, all IPs are filtered", addr, port);
    //         let err = io::Error::new(ErrorKind::Other, "resolved to empty address, all IPs are filtered");
    //         Err(err)
    //     } else {
    //         debug!("Resolved {}:{} => {:?}", addr, port, vaddr);
    //         Ok(vaddr)
    //     }
    // })
    // .await?

    let mut vaddr = Vec::new();
    for addr in (addr, port).to_socket_addrs()? {
        let ip = addr.ip();

        if check_forbidden {
            let forbidden_ip = &context.config().forbidden_ip;
            if forbidden_ip.contains(&ip) {
                debug!("Resolved {} => {}, which is skipped by forbidden_ip", addr, ip);
                continue;
            }
        }
        vaddr.push(addr);
    }

    if vaddr.is_empty() {
        error!("Failed to resolve {}:{}, all IPs are filtered", addr, port);
        let err = io::Error::new(ErrorKind::Other, "resolved to empty address, all IPs are filtered");
        Err(err)
    } else {
        debug!("Resolved {}:{} => {:?}", addr, port, vaddr);
        Ok(vaddr)
    }
}
