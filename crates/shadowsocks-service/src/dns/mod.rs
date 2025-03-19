//! DNS resolvers

#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::ResolverOpts;
use log::trace;
use shadowsocks::{dns_resolver::DnsResolver, net::ConnectOpts};

use crate::config::DnsConfig;

#[allow(unused_variables, dead_code)]
pub async fn build_dns_resolver(
    dns: DnsConfig,
    ipv6_first: bool,
    dns_cache_size: Option<usize>,
    connect_opts: &ConnectOpts,
) -> Option<DnsResolver> {
    match dns {
        DnsConfig::System => {
            #[cfg(feature = "hickory-dns")]
            if crate::hint_support_default_system_resolver() {
                use log::warn;
                use std::env;

                let force_system_builtin = match env::var("SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN") {
                    Ok(mut v) => {
                        v.make_ascii_lowercase();
                        v == "1" || v == "true"
                    }
                    Err(..) => false,
                };

                if !force_system_builtin {
                    let mut opts_opt = None;
                    if let Some(dns_cache_size) = dns_cache_size {
                        let mut opts = ResolverOpts::default();
                        opts.cache_size = dns_cache_size;
                        opts_opt = Some(opts);
                    }

                    return match DnsResolver::hickory_dns_system_resolver(opts_opt, connect_opts.clone()).await {
                        Ok(r) => Some(r),
                        Err(err) => {
                            warn!(
                                "initialize hickory-dns DNS system resolver failed, fallback to default system resolver, error: {}",
                                err
                            );
                            None
                        }
                    };
                }
            }

            trace!("initialized DNS system resolver builtin");

            None
        }
        #[cfg(feature = "hickory-dns")]
        DnsConfig::HickoryDns(dns) => {
            let mut opts_opt = None;
            if let Some(dns_cache_size) = dns_cache_size {
                let mut opts = ResolverOpts::default();
                opts.cache_size = dns_cache_size;
                opts_opt = Some(opts);
            }

            match DnsResolver::hickory_resolver(dns, opts_opt, connect_opts.clone()).await {
                Ok(r) => Some(r),
                Err(err) => {
                    use log::warn;

                    warn!(
                        "initialize hickory-dns DNS resolver failed, fallback to default system resolver, error: {}",
                        err
                    );
                    None
                }
            }
        }
        #[cfg(feature = "local-dns")]
        DnsConfig::LocalDns(ns) => {
            use crate::local::dns::dns_resolver::DnsResolver as LocalDnsResolver;
            use shadowsocks::config::Mode;

            trace!("initializing direct DNS resolver for {}", ns);

            let mut resolver = LocalDnsResolver::new(ns);
            resolver.set_mode(Mode::TcpAndUdp);
            resolver.set_ipv6_first(ipv6_first);
            resolver.set_connect_opts(connect_opts.clone());

            Some(DnsResolver::custom_resolver(resolver))
        }
    }
}
