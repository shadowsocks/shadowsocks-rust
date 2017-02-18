//! Asynchronous DNS resolver

use std::io;

use futures::{Future, BoxFuture};

use tokio_core::reactor::Handle;

use domain::resolv::Resolver;
use domain::resolv::lookup::{lookup_host, LookupHost};
use domain::bits::DNameBuf;

use std::net::IpAddr;

pub fn resolve(addr: &str, handle: &Handle) -> BoxFuture<IpAddr, io::Error> {
    let dname = addr.parse::<DNameBuf>().unwrap();
    let resolv = Resolver::new(handle).unwrap();
    resolv.spawn(move |task| {
        trace!("Going to resolve \"{}\"", dname);

        let hst: BoxFuture<LookupHost, io::Error> = lookup_host(task, &dname);
        // FIXME: rustc may not treat BoxFuture as a Future .. BUG?
        <BoxFuture<LookupHost, io::Error> as Future>::map_err(hst, |err| {
                io::Error::new(io::ErrorKind::Other, err.to_string())
            })
            .and_then(move |hosts| {
                match hosts.iter().next() {
                    Some(addr) => {
                        trace!("Resolved \"{}\" as {}", dname, addr);
                        Ok(addr)
                    }
                    None => {
                        let err = io::Error::new(io::ErrorKind::Other,
                                                 format!("Failed to resolve \"{}\"", dname));
                        Err(err)
                    }
                }
            })
    })
}