//! Asynchronous DNS resolver

use std::io;

use futures::{Future, BoxFuture};

use tokio_core::reactor::Handle;

use domain::resolv::Resolver;
use domain::resolv::lookup::lookup_host;
use domain::bits::DNameBuf;

use std::net::IpAddr;

pub fn resolve(addr: &str, handle: &Handle) -> BoxFuture<IpAddr, io::Error> {
    let dname = addr.parse::<DNameBuf>().unwrap();
    let resolv = Resolver::new(handle);

    trace!("Going to resolve \"{}\"", dname);

    lookup_host(resolv, &dname)
        .map_err(From::from)
        .and_then(move |hosts| match hosts.iter().next() {
                      Some(addr) => {
            trace!("Resolved \"{}\" as {}", dname, addr);
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
