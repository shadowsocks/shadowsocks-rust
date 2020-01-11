//! Asynchronous DNS resolver

use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use log::{debug, error, trace};
use tokio::{self, runtime::Handle};
use trust_dns_resolver::{config::ResolverConfig, TokioAsyncResolver};

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
                    "Initializing DNS resolver with config {:?} opts {:?}",
                    conf,
                    ResolverOpts::default()
                );
                TokioAsyncResolver::new(conf, ResolverOpts::default(), rt)
            } else {
                use trust_dns_resolver::system_conf::read_system_conf;
                // use the system resolver configuration
                let (config, opts) = read_system_conf().expect("Failed to read global dns sysconf");
                trace!(
                    "Initializing DNS resolver with system-config {:?} opts {:?}",
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
                    "Initializing DNS resolver with config {:?} opts {:?}",
                    conf,
                    ResolverOpts::default()
                );
                TokioAsyncResolver::new(conf, ResolverOpts::default(), rt)
            } else {
                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                trace!(
                    "Initializing DNS resolver with google-config {:?} opts {:?}",
                    ResolverConfig::google(),
                    ResolverOpts::default()
                );
                TokioAsyncResolver::new(ResolverConfig::google(), ResolverOpts::default(), rt)
            }
        }
    }
    .await
    .map_err(|err| {
        error!("Failed to create trust-dns DNS Resolver, {}", err);
        Error::new(ErrorKind::Other, "failed to create trust-dns DNS resolver")
    })
}

/// Perform a DNS resolution
pub async fn resolve(
    context: &Context,
    addr: &str,
    port: u16,
    check_forbidden: bool,
) -> io::Result<impl Iterator<Item = SocketAddr>> {
    match context.dns_resolver().lookup_ip(addr).await {
        Err(err) => {
            let err = Error::new(ErrorKind::Other, format!("dns resolve {}:{}, {}", addr, port, err));
            Err(err)
        }
        Ok(lookup_result) => {
            let mut vaddr = Vec::new();
            for ip in lookup_result.iter() {
                if check_forbidden && context.check_forbidden_ip(&ip) {
                    debug!("Resolved {} => {}, which is skipped by forbidden_ip", addr, ip);
                    continue;
                }

                vaddr.push(SocketAddr::new(ip, port));
            }

            if vaddr.is_empty() {
                let err = Error::new(
                    ErrorKind::Other,
                    format!("resolved {}:{}, but all IPs are filtered", addr, port),
                );
                Err(err)
            } else {
                debug!("Resolved {}:{} => {:?}", addr, port, vaddr);
                Ok(vaddr.into_iter())
            }
        }
    }
}
