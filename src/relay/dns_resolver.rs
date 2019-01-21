//! Asynchronous DNS resolver

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use futures::Future;
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
                AsyncResolver::new(conf, ResolverOpts::default())
            } else {
                use trust_dns_resolver::system_conf::read_system_conf;
                // use the system resolver configuration
                let (config, opts) = read_system_conf().expect("Failed to read global dns sysconf");
                AsyncResolver::new(config, opts)
            }
        }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
        {
            // Directly reference the config types
            use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

            if let Some(conf) = dns {
                AsyncResolver::new(conf, ResolverOpts::default())
            } else {
                // Get a new resolver with the google nameservers as the upstream recursive resolvers
                AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default())
            }
        }
    };

    // NOTE: resolving will always be called inside a future.
    tokio::spawn(bg);

    resolver
}

fn inner_resolve(
    context: SharedContext,
    addr: &str,
    port: u16,
    check_forbidden: bool,
) -> impl Future<Item = Vec<SocketAddr>, Error = io::Error> + Send {
    // let owned_addr = addr.to_owned();
    let cloned_context = context.clone();
    context.dns_resolver().lookup_ip(addr).then(move |r| match r {
        Err(err) => {
            // error!("Failed to resolve {}, err: {}", owned_addr, err);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("dns resolve error: {}", err),
            ))
        }
        Ok(lookup_result) => {
            let mut vaddr = Vec::new();
            for ip in lookup_result.iter() {
                if check_forbidden {
                    let forbidden_ip = &cloned_context.config().forbidden_ip;
                    if forbidden_ip.contains(&ip) {
                        // debug!("Resolved {} => {}, which is skipped by forbidden_ip", owned_addr, ip);
                        continue;
                    }
                }
                vaddr.push(SocketAddr::new(ip, port));
            }

            if vaddr.is_empty() {
                let err = io::Error::new(
                    ErrorKind::Other,
                    // format!("resolved {} to empty address, all IPs are filtered", owned_addr),
                    "resolved to empty address, all IPs are filtered",
                );
                Err(err)
            } else {
                // debug!("Resolved {} => {:?}", owned_addr, vaddr);
                Ok(vaddr)
            }
        }
    })
}

/// Resolve address to IP
pub fn resolve(
    context: SharedContext,
    addr: &str,
    port: u16,
    check_forbidden: bool,
) -> impl Future<Item = Vec<SocketAddr>, Error = io::Error> + Send {
    inner_resolve(context, addr, port, check_forbidden)
}
