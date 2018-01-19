//! Asynchronous DNS resolver

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use futures::{future, Future};

use futures_cpupool::CpuPool;

use relay::{boxed_future, BoxIoFuture};
use relay::Context;

lazy_static! {
    static ref GLOBAL_DNS_CPU_POOL: CpuPool = CpuPool::new_num_cpus();
}

pub fn resolve(addr: &str, port: u16, check_forbidden: bool) -> BoxIoFuture<Vec<SocketAddr>> {
    // FIXME: Sometimes addr is actually an IpAddr!
    if let Ok(addr) = addr.parse::<IpAddr>() {
        if !check_forbidden {
            return boxed_future(future::finished(vec![SocketAddr::new(addr, port)]));
        }

        let result = Context::with(move |ctx| {
                                       let forbidden_ip = &ctx.forbidden_ip();

                                       if forbidden_ip.contains(&addr) {
                                           let err = io::Error::new(ErrorKind::Other,
                                                                    format!("{} is forbidden, all IPs are filtered",
                                                                            addr));
                                           Err(err)
                                       } else {
                                           Ok(vec![SocketAddr::new(addr, port)])
                                       }
                                   });

        return boxed_future(future::done(result));
    }

    trace!("Going to resolve \"{}:{}\"", addr, port);
    let owned_addr = addr.to_owned();
    let fut = GLOBAL_DNS_CPU_POOL.spawn_fn(move || match (owned_addr.as_str(), port).to_socket_addrs() {
                                               Ok(a) => Ok((owned_addr, a)),
                                               Err(err) => {
                                                   error!("Failed to resolve {}, {}", owned_addr, err);
                                                   Err(err)
                                               }
                                           })
                                 .and_then(move |(owned_addr, addr_iter)| {
                                               let v =
                                                   if !check_forbidden {
                                                       addr_iter.collect::<Vec<SocketAddr>>()
                                                   } else {
                                                       Context::with(move |ctx| {
                                                           let forbidden_ip = ctx.forbidden_ip();
                                                           addr_iter.filter(|addr| {
                                                                  let filtered = forbidden_ip.contains(&addr.ip());
                                                                  if filtered {
                                                                      error!("{} is forbidden and ignored", addr.ip());
                                                                  }
                                                                  !filtered
                                                              })
                                                      .collect::<Vec<SocketAddr>>()
                                                       })
                                                   };

                                               if v.is_empty() {
                                                   let err =
                                                       io::Error::new(io::ErrorKind::Other,
                                                                      format!("resolved \"{}:{}\" to empty address",
                                                                              owned_addr, port));
                                                   Err(err)
                                               } else {
                                                   debug!("Resolved \"{}\" => {:?}", owned_addr, v);
                                                   Ok(v)
                                               }
                                           });

    boxed_future(fut)
}
