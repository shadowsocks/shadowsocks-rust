//! Asynchronous DNS resolver

mod trust_dns_resolver;

pub use self::trust_dns_resolver::{create_resolver, resolve};
