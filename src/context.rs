//! Shadowsocks Server Context

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use lru_cache::LruCache;
use trust_dns_resolver::AsyncResolver;

use crate::{config::Config, plugin::Plugin, relay::dns_resolver::create_resolver};

type DnsQueryCache = LruCache<u16, (SocketAddr, Instant)>;

#[derive(Clone)]
pub struct Context {
    config: Config,
    dns_resolver: Arc<AsyncResolver>,
    dns_query_cache: Option<Arc<Mutex<DnsQueryCache>>>,
    plugins: Arc<Vec<Plugin>>,
}

pub type SharedContext = Arc<Context>;

impl Context {
    pub fn new(config: Config) -> Context {
        let resolver = create_resolver(config.get_dns_config());
        Context {
            config,
            dns_resolver: Arc::new(resolver),
            dns_query_cache: None,
            plugins: Arc::new(Vec::new()),
        }
    }

    pub fn new_dns(config: Config) -> Context {
        let resolver = create_resolver(config.get_dns_config());
        Context {
            config,
            dns_resolver: Arc::new(resolver),
            dns_query_cache: Some(Arc::new(Mutex::new(LruCache::new(1024)))),
            plugins: Arc::new(Vec::new()),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    pub fn dns_resolver(&self) -> &AsyncResolver {
        &*self.dns_resolver
    }

    pub fn dns_query_cache(&self) -> MutexGuard<DnsQueryCache> {
        self.dns_query_cache.as_ref().unwrap().lock().unwrap()
    }

    pub fn set_plugins(&mut self, plugins: Vec<Plugin>) {
        self.plugins = Arc::new(plugins);
    }
}
