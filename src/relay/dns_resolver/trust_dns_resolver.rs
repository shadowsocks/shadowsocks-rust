//! Asynchronous DNS resolver

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use log::{debug, error, trace};
use tokio;
use trust_dns_resolver::{config::ResolverConfig, AsyncResolver};

use crate::context::SharedContext;

pub fn create_resolver(dns: Option<ResolverConfig>) -> AsyncResolver {
    let (resolver, bg) = {
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
                AsyncResolver::new(conf, ResolverOpts::default())
            } else {
                use trust_dns_resolver::system_conf::read_system_conf;
                // use the system resolver configuration
                let (config, opts) = read_system_conf().expect("Failed to read global dns sysconf");
                trace!(
                    "Initializing DNS resolver with system-config {:?} opts {:?}",
                    config,
                    opts
                );

                AsyncResolver::new(config, opts)
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
                AsyncResolver::new(conf, ResolverOpts::default())
            } else {
                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                trace!(
                    "Initializing DNS resolver with google-config {:?} opts {:?}",
                    ResolverConfig::google(),
                    ResolverOpts::default()
                );
                AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default())
            }
        }
    };

    // NOTE: resolving will always be called inside a future.
    tokio::spawn(bg);

    resolver
}

async fn inner_resolve(
    context: SharedContext,
    addr: &str,
    port: u16,
    check_forbidden: bool,
) -> io::Result<Vec<SocketAddr>> {
    match context.dns_resolver().lookup_ip(addr).await {
        Err(err) => {
            error!("Failed to resolve {}:{}, err: {}", addr, port, err);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("dns resolve error: {}", err),
            ))
        }
        Ok(lookup_result) => {
            let mut vaddr = Vec::new();
            for ip in lookup_result.iter() {
                if check_forbidden {
                    let forbidden_ip = &context.config().forbidden_ip;
                    if forbidden_ip.contains(&ip) {
                        debug!("Resolved {} => {}, which is skipped by forbidden_ip", addr, ip);
                        continue;
                    }
                }
                vaddr.push(SocketAddr::new(ip, port));
            }

            if vaddr.is_empty() {
                error!("Failed to resolve {}:{}, all IPs are filtered", addr, port);
                let err = io::Error::new(ErrorKind::Other, "resolved to empty address, all IPs are filtered");
                Err(err)
            } else {
                debug!("Resolved {}:{} => {:?}", addr, port, vaddr);
                Ok(vaddr)
            }
        }
    }
}

/// Resolve address to IP
pub async fn resolve(
    context: SharedContext,
    addr: &str,
    port: u16,
    check_forbidden: bool,
) -> io::Result<Vec<SocketAddr>> {
    inner_resolve(context, addr, port, check_forbidden).await
}
