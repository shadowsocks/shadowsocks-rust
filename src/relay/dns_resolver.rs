//! Asynchronous DNS resolver

use std::io;
use std::net::{IpAddr, ToSocketAddrs};

use futures::future;

use futures_cpupool::CpuPool;

use relay::{boxed_future, BoxIoFuture};

lazy_static! {
    static ref GLOBAL_DNS_CPU_POOL: CpuPool = CpuPool::new_num_cpus();
}

pub fn resolve(addr: &str) -> BoxIoFuture<Vec<IpAddr>> {
    // FIXME: Sometimes addr is actually an IpAddr!
    if let Ok(addr) = addr.parse::<IpAddr>() {
        return boxed_future(future::finished(vec![addr]));
    }

    trace!("Going to resolve \"{}\"", addr);
    let owned_addr = format!("{}:0", addr);

    let fut = GLOBAL_DNS_CPU_POOL.spawn_fn(move || {
        owned_addr.to_socket_addrs().and_then(|addr_iter| {
            let v = addr_iter.map(|addr| addr.ip()).collect::<Vec<IpAddr>>();
            if v.is_empty() {
                let err = io::Error::new(io::ErrorKind::Other, format!("Failed to resolve \"{}\"", owned_addr));
                Err(err)
            } else {
                trace!("Resolved \"{}\" => {:?}", owned_addr, v);
                Ok(v)
            }
        })
    });

    boxed_future(fut)
}
