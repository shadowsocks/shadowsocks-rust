//! Shadowsocks service context

use std::{io, net::SocketAddr, sync::Arc};

use crate::dns_resolver::DnsResolver;

/// Service context
pub struct Context {
    // trust-dns resolver, which supports REAL asynchronous resolving, and also customizable
    dns_resolver: Arc<DnsResolver>,

    // Connect IPv6 address first
    ipv6_first: bool,
}

/// `Context` for sharing between services
pub type SharedContext = Arc<Context>;

impl Context {
    /// Create a new `Context` for `Client` or `Server`
    pub fn new() -> Context {
        Context {
            dns_resolver: Arc::new(DnsResolver::system_resolver()),
            ipv6_first: false,
        }
    }

    /// Create a new `Context` shared
    pub fn new_shared() -> SharedContext {
        SharedContext::new(Context::new())
    }

    /// Set a DNS resolver
    ///
    /// The resolver should be wrapped in an `Arc`, because it could be shared with the other servers
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        self.dns_resolver = resolver;
    }

    /// Get the DNS resolver
    pub fn dns_resolver(&self) -> &Arc<DnsResolver> {
        &self.dns_resolver
    }

    /// Resolves DNS address to `SocketAddr`s
    #[allow(clippy::needless_lifetimes)]
    pub async fn dns_resolve<'a>(&self, addr: &'a str, port: u16) -> io::Result<impl Iterator<Item = SocketAddr> + 'a> {
        self.dns_resolver.resolve(addr, port).await
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        self.ipv6_first = ipv6_first;
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn ipv6_first(&self) -> bool {
        self.ipv6_first
    }
}
