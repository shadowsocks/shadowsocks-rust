//! Shadowsocks Server Context

use std::sync::Arc;

use trust_dns_resolver::AsyncResolver;

use crate::{config::Config, relay::dns_resolver::create_resolver};

#[derive(Clone)]
pub struct Context {
    config: Config,
    dns_resolver: Arc<AsyncResolver>,
}

pub type SharedContext = Arc<Context>;

impl Context {
    pub fn new(config: Config) -> Context {
        let resolver = create_resolver(config.get_dns_config());
        Context {
            config,
            dns_resolver: Arc::new(resolver),
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
}
