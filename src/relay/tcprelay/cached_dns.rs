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

use std::sync::Arc;
// use std::sync::atomic::{AtomicOption, SeqCst};
use std::net::lookup_host;
use std::net::SocketAddr;

use coio::sync::Mutex;

use lru_cache::LruCache;

struct DnsLruCache {
    cache: LruCache<String, Vec<SocketAddr>>,
    totally_matched: usize,
    totally_missed: usize,
}

pub struct CachedDns {
    lru_cache: Arc<Mutex<DnsLruCache>>,
}

impl CachedDns {
    pub fn with_capacity(cache_capacity: usize) -> CachedDns {
        CachedDns {
            lru_cache: Arc::new(Mutex::new(DnsLruCache {
                cache: LruCache::new(cache_capacity),
                totally_missed: 0,
                totally_matched: 0,
            })),
        }
    }

    pub fn resolve(&self, addr_str: &str) -> Option<Vec<SocketAddr>> {
        {
            let mut cache = self.lru_cache.lock().unwrap();
            match cache.cache.get_mut(addr_str).map(|x| x.clone()) {
                Some(addrs) => {
                    cache.totally_matched += 1;
                    debug!("DNS cache matched!: {}", addr_str);
                    debug!("DNS cache matched: {}, missed: {}",
                           cache.totally_matched,
                           cache.totally_missed);
                    return Some(addrs);
                }
                None => {
                    cache.totally_missed += 1;
                    debug!("DNS cache missed!: {}", addr_str);
                    debug!("DNS cache matched: {}, missed: {}",
                           cache.totally_matched,
                           cache.totally_missed);
                }
            }
        }

        let addr_vec = match lookup_host(addr_str) {
            Ok(addrs) => addrs.collect::<Vec<SocketAddr>>(),
            Err(err) => {
                error!("Failed to resolve {}: {}", addr_str, err);
                return None;
            }
        };

        let cloned_mutex = self.lru_cache.clone();

        if addr_vec.is_empty() {
            error!("Failed to resolve {}", addr_str);
            return None;
        }
        let cloned_addrs = addr_vec.clone();

        let addr_string: String = addr_str.to_owned();
        {
            let mut cache = cloned_mutex.lock().unwrap();
            cache.cache.insert(addr_string, cloned_addrs);
        }
        Some(addr_vec)
    }
}

unsafe impl Send for CachedDns {}
unsafe impl Sync for CachedDns {}
