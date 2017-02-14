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

use std::net::{SocketAddr, ToSocketAddrs};
use std::io;

use futures;
use futures_cpupool::{CpuPool, CpuFuture};

use ip::IpAddr;

lazy_static! {
    pub static ref GLOBAL_DNS_RESOLVER: DnsResolver = DnsResolver::new();
}

fn socket_addr_to_ip(addr: SocketAddr) -> IpAddr {
    match addr {
        SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
        SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
    }
}

#[derive(Clone)]
pub struct DnsResolver {
    cpu_pool: CpuPool,
}

impl DnsResolver {
    /// Creates an DNS resolver
    fn new() -> DnsResolver {
        DnsResolver { cpu_pool: CpuPool::new_num_cpus() }
    }

    /// Resolves address asynchronously
    pub fn resolve(addr: &str) -> CpuFuture<IpAddr, io::Error> {
        let mixed_addr = format!("{}:0", addr);
        GLOBAL_DNS_RESOLVER.cpu_pool.spawn(futures::lazy(move || {
            match try!(mixed_addr.to_socket_addrs()).next() {
                Some(sock_addr) => {
                    let ipaddr = socket_addr_to_ip(sock_addr);
                    Ok(ipaddr)
                }
                None => {
                    let err = io::Error::new(io::ErrorKind::Other,
                                             format!("Failed to resolve \"{}\"", mixed_addr));
                    Err(err)
                }
            }
        }))
    }
}
