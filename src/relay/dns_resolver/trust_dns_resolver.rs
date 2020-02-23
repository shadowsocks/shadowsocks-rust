//! Asynchronous DNS resolver

use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use log::{error, trace};
use tokio::{self, runtime::Handle};
use trust_dns_resolver::{config::ResolverConfig, TokioAsyncResolver};

use super::tokio_dns_resolver::resolve as tokio_resolve;
use crate::context::Context;

/// Create a `trust-dns` asynchronous DNS resolver
pub async fn create_resolver(dns: Option<ResolverConfig>, rt: Handle) -> io::Result<TokioAsyncResolver> {
    {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
        {
            if let Some(conf) = dns {
                use trust_dns_resolver::config::ResolverOpts;
                trace!(
                    "initializing DNS resolver with config {:?} opts {:?}",
                    conf,
                    ResolverOpts::default()
                );
                TokioAsyncResolver::new(conf, ResolverOpts::default(), rt)
            } else {
                use trust_dns_resolver::system_conf::read_system_conf;
                // use the system resolver configuration
                let (config, opts) = match read_system_conf() {
                    Ok(o) => o,
                    Err(err) => {
                        error!("failed to initialize DNS resolver with system-config, error: {}", err);
                        return Err(err);
                    }
                };

                trace!(
                    "initializing DNS resolver with system-config {:?} opts {:?}",
                    config,
                    opts
                );

                TokioAsyncResolver::new(config, opts, rt)
            }
        }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
        {
            // Directly reference the config types
            use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

            if let Some(conf) = dns {
                trace!(
                    "initializing DNS resolver with config {:?} opts {:?}",
                    conf,
                    ResolverOpts::default()
                );
                TokioAsyncResolver::new(conf, ResolverOpts::default(), rt)
            } else {
                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                trace!(
                    "initializing DNS resolver with google-config {:?} opts {:?}",
                    ResolverConfig::google(),
                    ResolverOpts::default()
                );
                TokioAsyncResolver::new(ResolverConfig::google(), ResolverOpts::default(), rt)
            }
        }
    }
    .await
    .map_err(|err| {
        Error::new(
            ErrorKind::Other,
            format!("failed to create trust-dns DNS resolver, error: {}", err),
        )
    })
}

/// Perform a DNS resolution
pub async fn resolve(context: &Context, addr: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    match context.dns_resolver() {
        Some(resolver) => match resolver.lookup_ip(addr).await {
            Ok(lookup_result) => Ok(lookup_result.iter().map(|ip| SocketAddr::new(ip, port)).collect()),
            Err(err) => {
                let err = Error::new(
                    ErrorKind::Other,
                    format!("dns resolve {}:{} error: {}", addr, port, err),
                );
                Err(err)
            }
        },
        // Fallback to tokio's DNS resolver
        None => tokio_resolve(context, addr, port).await,
    }
}
