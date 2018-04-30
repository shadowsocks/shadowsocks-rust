//! Relay server in local and server side implementations.

use futures::Future;

pub mod tcprelay;
pub mod udprelay;
pub mod local;
pub mod server;
mod loadbalancing;
mod dns_resolver;
pub mod socks5;
mod utils;

fn boxed_future<T, E, F>(f: F) -> Box<Future<Item = T, Error = E> + Send + 'static>
    where F: Future<Item = T, Error = E> + Send + 'static
{
    Box::new(f)
}
