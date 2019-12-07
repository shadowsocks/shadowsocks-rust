//! Shadowsocks Server Context

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[cfg(feature = "trust-dns")]
use trust_dns_resolver::AsyncResolver;

use crate::config::Config;

#[cfg(feature = "trust-dns")]
use crate::relay::dns_resolver::create_resolver;

#[derive(Clone)]
pub struct SharedServerState {
    #[cfg(feature = "trust-dns")]
    dns_resolver: Arc<AsyncResolver>,
    server_running: Arc<AtomicBool>,
}

impl SharedServerState {
    #[allow(unused_variables)]
    pub fn new(config: &Config) -> SharedServerState {
        SharedServerState {
            #[cfg(feature = "trust-dns")]
            dns_resolver: Arc::new(create_resolver(config.get_dns_config())),
            server_running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Check if the server is still in running state
    pub fn server_running(&self) -> bool {
        self.server_running.load(Ordering::Acquire)
    }

    /// Stops the server, kills all detached running tasks
    pub fn server_stopped(&self) {
        self.server_running.store(false, Ordering::Release)
    }

    /// Get the global shared resolver
    #[cfg(feature = "trust-dns")]
    pub fn dns_resolver(&self) -> &AsyncResolver {
        &*self.dns_resolver
    }
}

/// Shared basic configuration for the whole server
pub struct Context {
    config: Config,
    server_state: SharedServerState,
}

/// Unique context thw whole server
pub type SharedContext = Arc<Context>;

impl Context {
    pub fn new(config: Config, server_state: SharedServerState) -> Context {
        Context { config, server_state }
    }

    pub fn new_shared(config: Config, server_state: SharedServerState) -> SharedContext {
        SharedContext::new(Context::new(config, server_state))
    }

    /// Config for TCP server
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Mutable Config for TCP server
    ///
    /// NOTE: Only for launching plugins
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Get the global shared resolver
    #[cfg(feature = "trust-dns")]
    pub fn dns_resolver(&self) -> &AsyncResolver {
        self.server_state.dns_resolver()
    }

    /// Check if the server is still in running state
    pub fn server_running(&self) -> bool {
        self.server_state.server_running()
    }

    /// Stops the server, kills all detached running tasks
    pub fn server_stopped(&self) {
        self.server_state.server_stopped()
    }
}
