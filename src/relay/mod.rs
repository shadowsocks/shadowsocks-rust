//! Relay server in local and server side implementations.

use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

use config::Config;
use futures::Future;
use tokio_core::reactor::Handle;

pub mod tcprelay;
pub mod udprelay;
pub mod local;
pub mod server;
mod loadbalancing;
mod dns_resolver;
pub mod socks5;
mod utils;

/// Alias for Boxed Future without Send
pub type BoxIoFuture<T> = Box<Future<Item = T, Error = io::Error>>;

fn boxed_future<T, E, F>(f: F) -> Box<Future<Item = T, Error = E>>
where
    F: Future<Item = T, Error = E> + 'static,
{
    Box::new(f)
}

scoped_thread_local!(static CONTEXT: Context);

/// Local server running context
pub struct Context {
    handle: Handle,
    config: Config,
}

impl Context {
    #[doc(hidden)]
    /// Creates a new Context
    pub fn new(handle: Handle, config: Config) -> Context {
        Context {
            handle: handle,
            config: config,
        }
    }

    /// Get the value in this context
    pub fn with<F, R>(f: F) -> R
    where
        F: FnOnce(&Context) -> R,
    {
        CONTEXT.with(f)
    }

    #[doc(hidden)]
    pub fn set<F, R>(ctx: &Context, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        CONTEXT.set(ctx, f)
    }


    /// Get Core handle
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Get config
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get forbidden IPs
    pub fn forbidden_ip(&self) -> &HashSet<IpAddr> {
        &self.config.forbidden_ip
    }
}
