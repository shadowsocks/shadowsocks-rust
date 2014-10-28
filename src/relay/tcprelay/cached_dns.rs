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

use std::sync::{Arc, Mutex};
// use std::sync::atomic::{AtomicOption, SeqCst};
use std::io::net::addrinfo::get_host_addresses;
use std::collections::lru_cache::LruCache;
use std::io::net::ip::IpAddr;

pub struct CachedDns {
    lru_cache: Arc<Mutex<LruCache<String, Vec<IpAddr>>>>,
}

impl CachedDns {
    pub fn new(cache_capacity: uint) -> CachedDns {
        CachedDns {
            lru_cache: Arc::new(Mutex::new(LruCache::new(cache_capacity))),
        }
    }

    pub fn resolve(&self, addr: &str) -> Option<Vec<IpAddr>> {
        let addr_string = addr.to_string();

        {
            let mut cache = self.lru_cache.lock();
            match cache.get(&addr_string).map(|x| x.clone()) {
                Some(addrs) => {
                    debug!("DNS cache matched!: {}", addr_string);
                    return Some(addrs)
                },
                None => {}
            }
        }

        debug!("DNS cache missed!: {}", addr_string);
        let addrs = match get_host_addresses(addr) {
            Ok(addrs) => addrs,
            Err(err) => {
                error!("Failed to resolve {}: {}", addr, err);
                return None;
            }
        };

        let cloned_mutex = self.lru_cache.clone();
        let cloned_addr = addrs.clone();
        spawn(proc() {
            let mut cache = cloned_mutex.lock();
            cache.put(addr_string, cloned_addr);
        });
        Some(addrs)
    }
}
