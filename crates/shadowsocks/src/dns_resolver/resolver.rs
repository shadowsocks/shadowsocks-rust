//! Resolver Alternatives

use std::{
    fmt::{self, Debug},
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    time::Instant,
};

use async_trait::async_trait;
use log::{log_enabled, trace, Level};
use tokio::net::lookup_host;
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::{config::ResolverConfig, TokioAsyncResolver};

/// Abstract DNS resolver
#[async_trait]
pub trait DnsResolve {
    /// Resolves `addr:port` to a list of `SocketAddr`
    async fn resolve(&self, addr: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// Collections of DNS resolver
pub enum DnsResolver {
    /// System Resolver, which is tokio's builtin resolver
    System,
    #[cfg(feature = "trust-dns")]
    /// Trust-DNS resolver
    TrustDns(TokioAsyncResolver),
    /// Customized Resolver
    Custom(Box<dyn DnsResolve + Send + Sync>),
}

impl Default for DnsResolver {
    fn default() -> DnsResolver {
        DnsResolver::system_resolver()
    }
}

impl Debug for DnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DnsResolver::System => f.write_str("System"),
            #[cfg(feature = "trust-dns")]
            DnsResolver::TrustDns(..) => f.write_str("TrustDns(..)"),
            DnsResolver::Custom(..) => f.write_str("Custom(..)"),
        }
    }
}

struct EmptyResolveResult;

impl Iterator for EmptyResolveResult {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        None
    }
}

// Resolved result
enum EitherResolved<A = EmptyResolveResult, B = EmptyResolveResult, C = EmptyResolveResult> {
    Tokio(A),
    TrustDns(B),
    Custom(C),
}

impl<A, B, C> Iterator for EitherResolved<A, B, C>
where
    A: Iterator<Item = SocketAddr>,
    B: Iterator<Item = SocketAddr>,
    C: Iterator<Item = SocketAddr>,
{
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        match *self {
            EitherResolved::Tokio(ref mut a) => a.next(),
            EitherResolved::TrustDns(ref mut b) => b.next(),
            EitherResolved::Custom(ref mut c) => c.next(),
        }
    }
}

impl DnsResolver {
    /// Use system DNS resolver. Tokio will call `getaddrinfo` in blocking pool.
    pub fn system_resolver() -> DnsResolver {
        DnsResolver::System
    }

    /// Use trust-dns DNS resolver (with DNS cache)
    #[cfg(feature = "trust-dns")]
    pub async fn trust_dns_resolver(dns: Option<ResolverConfig>, ipv6_first: bool) -> io::Result<DnsResolver> {
        use super::trust_dns_resolver::create_resolver;
        Ok(DnsResolver::TrustDns(create_resolver(dns, ipv6_first).await?))
    }

    /// Custom DNS resolver
    pub fn custom_resolver<R>(custom: R) -> DnsResolver
    where
        R: DnsResolve + Send + Sync + 'static,
    {
        DnsResolver::Custom(Box::new(custom) as Box<dyn DnsResolve + Send + Sync>)
    }

    /// Resolve address into `SocketAddr`s
    pub async fn resolve<'a>(&self, addr: &'a str, port: u16) -> io::Result<impl Iterator<Item = SocketAddr> + 'a> {
        struct ResolverLogger<'x, 'y> {
            resolver: &'x DnsResolver,
            addr: &'y str,
            port: u16,
            start_time: Option<Instant>,
        }

        impl<'x, 'y> ResolverLogger<'x, 'y> {
            fn new(resolver: &'x DnsResolver, addr: &'y str, port: u16) -> ResolverLogger<'x, 'y> {
                let start_time = if log_enabled!(Level::Trace) {
                    Some(Instant::now())
                } else {
                    None
                };

                ResolverLogger {
                    resolver,
                    addr,
                    port,
                    start_time,
                }
            }
        }

        impl<'x, 'y> Drop for ResolverLogger<'x, 'y> {
            fn drop(&mut self) {
                match self.start_time {
                    Some(start_time) => {
                        let end_time = Instant::now();
                        let elapsed = end_time - start_time;

                        match *self.resolver {
                            DnsResolver::System => {
                                trace!(
                                    "DNS resolved {}:{} with tokio {}s",
                                    self.addr,
                                    self.port,
                                    elapsed.as_secs_f32()
                                );
                            }
                            #[cfg(feature = "trust-dns")]
                            DnsResolver::TrustDns(..) => {
                                trace!(
                                    "DNS resolved {}:{} with trust-dns {}s",
                                    self.addr,
                                    self.port,
                                    elapsed.as_secs_f32()
                                );
                            }
                            DnsResolver::Custom(..) => {
                                trace!(
                                    "DNS resolved {}:{} with customized {}s",
                                    self.addr,
                                    self.port,
                                    elapsed.as_secs_f32()
                                );
                            }
                        }
                    }
                    None => match *self.resolver {
                        DnsResolver::System => {
                            trace!("DNS resolved {}:{} with tokio", self.addr, self.port);
                        }
                        #[cfg(feature = "trust-dns")]
                        DnsResolver::TrustDns(..) => {
                            trace!("DNS resolved {}:{} with trust-dns", self.addr, self.port);
                        }
                        DnsResolver::Custom(..) => {
                            trace!("DNS resolved {}:{} with customized", self.addr, self.port);
                        }
                    },
                }
            }
        }

        let _log_guard = ResolverLogger::new(self, addr, port);

        match *self {
            DnsResolver::System => match lookup_host((addr, port)).await {
                Ok(v) => Ok(EitherResolved::Tokio(v)),
                Err(err) => {
                    let err = Error::new(
                        ErrorKind::Other,
                        format!("dns resolve {}:{} error: {}", addr, port, err),
                    );
                    Err(err)
                }
            },
            #[cfg(feature = "trust-dns")]
            DnsResolver::TrustDns(ref resolver) => match resolver.lookup_ip(addr).await {
                Ok(lookup_result) => Ok(EitherResolved::TrustDns(
                    lookup_result.into_iter().map(move |ip| SocketAddr::new(ip, port)),
                )),
                Err(err) => {
                    let err = Error::new(
                        ErrorKind::Other,
                        format!("dns resolve {}:{} error: {}", addr, port, err),
                    );
                    Err(err)
                }
            },
            DnsResolver::Custom(ref resolver) => match resolver.resolve(addr, port).await {
                Ok(v) => Ok(EitherResolved::Custom(v.into_iter())),
                Err(err) => {
                    let err = Error::new(
                        ErrorKind::Other,
                        format!("dns resolve {}:{} error: {}", addr, port, err),
                    );
                    Err(err)
                }
            },
        }
    }

    /// Check if currently using system resolver
    pub fn is_system_resolver(&self) -> bool {
        matches!(*self, DnsResolver::System)
    }
}
