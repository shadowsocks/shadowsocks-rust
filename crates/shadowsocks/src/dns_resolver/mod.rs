//! Asynchronous DNS resolver
#![macro_use]

use cfg_if::cfg_if;

mod tokio_dns_resolver;

cfg_if! {
    if #[cfg(feature = "trust-dns")] {
        mod trust_dns_resolver;

        /// Use trust-dns DNS resolver (with DNS cache)
        pub use self::trust_dns_resolver::{create_resolver, resolve};
    } else {

        /// Use tokio's builtin DNS resolver
        pub use self::tokio_dns_resolver::resolve;
    }
}

/// Helper macro for resolving host and then process each addresses
#[macro_export]
macro_rules! lookup_then {
    ($context:expr, $addr:expr, $port:expr, |$resolved_addr:ident| $body:block) => {{
        let mut result = None;

        for $resolved_addr in $context.dns_resolve($addr, $port).await? {
            match $body {
                Ok(r) => {
                    result = Some(Ok(($resolved_addr, r)));
                    break;
                }
                Err(err) => {
                    result = Some(Err(err));
                }
            }
        }

        result.expect("resolved empty address")
    }};
}
