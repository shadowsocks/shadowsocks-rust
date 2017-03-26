//! Relay server in local and server side implementations.

use std::io;

use futures::Future;

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
    where F: Future<Item = T, Error = E> + 'static
{
    Box::new(f)
}
