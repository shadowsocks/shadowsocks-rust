//! Asynchronous DNS resolver
#![macro_use]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "trust-dns")] {
        mod trust_dns_resolver;

        pub use self::trust_dns_resolver::{create_resolver, resolve};
    } else {
        mod tokio_dns_resolver;

        pub use self::tokio_dns_resolver::resolve;
    }
}

/// Helper macro for resolving host and then process each addresses
#[macro_export]
macro_rules! lookup_then {
    ($context:expr, $addr:expr, $port:expr, $check_forbidden:expr, |$resolved_addr:ident| $body:block) => {{
        use crate::relay::dns_resolver::resolve;

        let mut result = None;

        for $resolved_addr in resolve($context, $addr, $port, $check_forbidden).await? {
            match $body {
                Ok(r) => {
                    result = Some(Ok(r));
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
