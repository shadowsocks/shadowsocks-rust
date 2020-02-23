//! Asynchronous DNS resolver
#![macro_use]

use std::{io, net::SocketAddr};

use cfg_if::cfg_if;

use crate::{config::ServerAddr, context::Context};

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

/// Helper macro for resolving host and then process each addresses
#[macro_export]
macro_rules! lookup_outbound_then {
    ($context:expr, $addr:expr, $port:expr, |$resolved_addr:ident| $body:block) => {{
        use std::io::{Error, ErrorKind};

        let mut result = None;

        for $resolved_addr in $context.dns_resolve($addr, $port).await? {
            if $context.check_resolved_outbound_blocked(&$resolved_addr) {
                let err = Error::new(
                    ErrorKind::Other,
                    format!(
                        "outbound {}:{} resolved to {} is blocked by ACL rules",
                        $addr, $port, $resolved_addr
                    ),
                );
                result = Some(Err(err));
                continue;
            }

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

/// Resolve `ServerAddr` for `bind()`
pub async fn resolve_bind_addr(context: &Context, addr: &ServerAddr) -> io::Result<SocketAddr> {
    match addr {
        ServerAddr::SocketAddr(ref a) => Ok(*a),
        ServerAddr::DomainName(ref dname, port) => {
            let addrs = self::resolve(context, dname, *port).await?;
            Ok(addrs[0])
        }
    }
}
