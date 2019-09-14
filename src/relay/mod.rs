//! Relay server in local and server side implementations.

use futures::Future;

pub mod dns;
pub(crate) mod dns_resolver;
mod loadbalancing;
pub mod local;
pub mod server;
pub mod socks5;
pub mod tcprelay;
pub mod udprelay;
mod utils;

pub fn boxed_future<T, E, F>(f: F) -> Box<dyn Future<Item=T, Error=E> + Send + 'static>
where
    F: Future<Item = T, Error = E> + Send + 'static,
{
    Box::new(f)
}
