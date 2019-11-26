//! Shadowsocks Server Context

use std::sync::Arc;

#[cfg(futures = "trust-dns")]
use trust_dns_resolver::AsyncResolver;

use crate::config::Config;

#[cfg(futures = "trust-dns")]
use crate::relay::dns_resolver::create_resolver;

#[cfg(futures = "trust-dns")]
#[derive(Clone)]
pub struct Context {
    config: Config,
    dns_resolver: Arc<AsyncResolver>,
}

#[cfg(not(futures = "trust-dns"))]
#[derive(Clone)]
pub struct Context {
    config: Config,
}

pub type SharedContext = Arc<Context>;

impl Context {
    #[cfg(futures = "trust-dns")]
    pub fn new(config: Config) -> Context {
        let resolver = create_resolver(config.get_dns_config());
        Context {
            config,
            dns_resolver: Arc::new(resolver),
        }
    }

    #[cfg(not(futures = "trust-dns"))]
    pub fn new(config: Config) -> Context {
        Context { config }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    #[cfg(futures = "trust-dns")]
    pub fn dns_resolver(&self) -> &AsyncResolver {
        &*self.dns_resolver
    }
}
