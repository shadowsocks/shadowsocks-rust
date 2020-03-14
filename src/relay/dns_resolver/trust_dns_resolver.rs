//! Asynchronous DNS resolver

use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use log::{error, trace};
use tokio::{self, runtime::Handle};
use trust_dns_resolver::{
    config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

use super::tokio_dns_resolver::resolve as tokio_resolve;
use crate::context::Context;

/// Create a `trust-dns` asynchronous DNS resolver
pub async fn create_resolver(
    dns: Option<ResolverConfig>,
    timeout: Option<Duration>,
    ipv6_first: bool,
    rt: Handle,
) -> io::Result<TokioAsyncResolver> {
    let mut resolver_opts = ResolverOpts::default();
    if let Some(d) = timeout {
        resolver_opts.timeout = d;
    }

    if ipv6_first {
        resolver_opts.ip_strategy = LookupIpStrategy::Ipv6thenIpv4;
    }

    {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
        {
            if let Some(conf) = dns {
                trace!(
                    "initializing DNS resolver with config {:?} opts {:?}",
                    conf,
                    resolver_opts
                );
                TokioAsyncResolver::new(conf, resolver_opts, rt)
            } else {
                use trust_dns_resolver::system_conf::read_system_conf;
                // use the system resolver configuration
                let (config, opts) = match read_system_conf() {
                    Ok(o) => o,
                    Err(err) => {
                        error!("failed to initialize DNS resolver with system-config, error: {}", err);

                        // From::from is required because on error type is different on Windows
                        #[allow(clippy::identity_conversion)]
                        return Err(From::from(err));
                    }
                };

                // NOTE: timeout will be set by config (for example, /etc/resolv.conf on UNIX-like system)

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
            if let Some(conf) = dns {
                trace!(
                    "initializing DNS resolver with config {:?} opts {:?}",
                    conf,
                    resolver_opts
                );
                TokioAsyncResolver::new(conf, resolver_opts, rt)
            } else {
                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                trace!(
                    "initializing DNS resolver with google-config {:?} opts {:?}",
                    ResolverConfig::google(),
                    resolver_opts
                );
                TokioAsyncResolver::new(ResolverConfig::google(), resolver_opts, rt)
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
