// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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