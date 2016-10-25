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
use std::sync::{Arc, Mutex};
use std::io;

use relay::BoxIoFuture;

use lru_cache::LruCache;

use futures::{self, Future};
use futures_cpupool::CpuPool;

use ip::IpAddr;

fn socket_addr_to_ip(addr: SocketAddr) -> IpAddr {
    match addr {
        SocketAddr::V4(v4) => IpAddr::V4(v4.ip().clone()),
        SocketAddr::V6(v6) => IpAddr::V6(v6.ip().clone()),
    }
}

#[derive(Clone)]
pub struct DnsResolver {
    cpu_pool: CpuPool,
    dns_cache: Arc<Mutex<LruCache<String, IpAddr>>>,
}

impl DnsResolver {
    /// Creates an DNS resolver
    pub fn new(cache_size: usize) -> DnsResolver {
        DnsResolver {
            cpu_pool: CpuPool::new_num_cpus(),
            dns_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        }
    }

    /// Resolves address asynchronously
    pub fn resolve(&self, addr: &str) -> BoxIoFuture<IpAddr> {
        let dns_cache = self.dns_cache.clone();

        let mut guard = self.dns_cache.lock().unwrap();
        match guard.get_mut(addr) {
            Some(addr) => futures::finished(addr.clone()).boxed(),
            None => {
                let addr = addr.to_owned();
                self.cpu_pool
                    .spawn(futures::lazy(move || {
                        let mixed_addr = format!("{}:0", addr);
                        match try!(mixed_addr.to_socket_addrs()).next() {
                            Some(sock_addr) => {
                                let mut guard = dns_cache.lock().unwrap();
                                let ipaddr = socket_addr_to_ip(sock_addr);
                                guard.insert(addr, ipaddr);
                                Ok(ipaddr)
                            }
                            None => {
                                let err = io::Error::new(io::ErrorKind::Other, "Failed to resolve address");
                                Err(err)
                            }
                        }
                    }))
                    .boxed()
            }
        }
    }
}
