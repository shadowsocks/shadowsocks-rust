// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

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

#[phase(plugin, link)]
extern crate log;

use std::io::net::addrinfo::get_host_addresses;
use std::collections::lru_cache::LruCache;
use std::io::net::ip::IpAddr;

const DNS_CACHE_CAPACITY: uint = 200;

pub struct CachedDns {
    lru_cache: LruCache<String, IpAddr>,
}

impl CachedDns {
    pub fn new() -> CachedDns {
        CachedDns {
            lru_cache: LruCache::new(DNS_CACHE_CAPACITY),
        }
    }

    pub fn resolve(&mut self, addr: &str) -> Option<IpAddr> {
        match self.lru_cache.get(&addr.to_string()).map(|x| *x) {
            Some(a) => {
                Some(a.clone())
            },
            None => {
                let ipaddr = match get_host_addresses(addr) {
                    Ok(addr_list) => {
                        addr_list[0]
                    },
                    Err(err) => {
                        error!("Error while resolving {}: {}", addr, err);
                        return None
                    }
                };
                self.lru_cache.put(addr.to_string(), ipaddr);
                Some(ipaddr)
            }
        }
    }
}
