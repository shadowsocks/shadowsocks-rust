//! Asynchronous DNS resolver

use std::io;
use std::time::Duration;
use std::cell::RefCell;

use futures::{Future, BoxFuture};
use futures::future;

use tokio_core::reactor::Handle;

use domain::resolv::Resolver;
use domain::resolv::lookup::lookup_host;
use domain::bits::DNameBuf;

use lru_time_cache::LruCache;

use std::net::IpAddr;

// Global DNS cache.
// Cache for 5mins and store at most 128 entries
thread_local!(static GLOBAL_DNS_CACHE: RefCell<LruCache<String, IpAddr>>
    = RefCell::new(LruCache::with_expiry_duration_and_capacity(Duration::from_secs(5 * 60), 128)));

pub fn resolve(addr: &str, handle: &Handle) -> BoxFuture<IpAddr, io::Error> {
    let cached_addr = GLOBAL_DNS_CACHE.with(|c| {
                                                let mut xc = c.borrow_mut();
                                                xc.get(addr).map(|x| *x)
                                            });

    if let Some(addr) = cached_addr {
        return future::finished(addr).boxed();
    }

    let dname = match addr.parse::<DNameBuf>() {
        Ok(dname) => dname,
        Err(err) => return future::err(io::Error::new(io::ErrorKind::Other, err)).boxed(),
    };
    let resolv = Resolver::new(handle);

    trace!("Going to resolve \"{}\"", dname);

    lookup_host(resolv, &dname)
        .map_err(From::from)
        .and_then(move |hosts| match hosts.iter().next() {
                      Some(addr) => {
                          trace!("Resolved \"{}\" as {}", dname, addr);

                          GLOBAL_DNS_CACHE.with(|c| {
                                                    let mut xc = c.borrow_mut();
                                                    xc.insert(dname.to_string(), addr);
                                                });

                          Ok(addr)
                      }
                      None => {
                          let err = io::Error::new(io::ErrorKind::Other,
                                                   format!("Failed to resolve \"{}\"", dname));
                          Err(err)
                      }
                  })
        .boxed()
}
