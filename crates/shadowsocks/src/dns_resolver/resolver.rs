//! Resolver Alternatives

#[cfg(feature = "hickory-dns")]
use std::sync::Arc;
use std::{
    fmt::{self, Debug},
    io::{self, Error, ErrorKind},
    net::SocketAddr,
    time::Instant,
};

#[cfg(feature = "hickory-dns")]
use arc_swap::ArcSwap;
use cfg_if::cfg_if;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::ResolverConfig;
#[cfg(feature = "hickory-dns")]
use hickory_resolver::config::ResolverOpts;
#[cfg(all(feature = "hickory-dns", unix, not(target_os = "android")))]
use log::error;
use log::{log_enabled, trace, Level};
use tokio::net::lookup_host;
#[cfg(all(feature = "hickory-dns", unix, not(target_os = "android")))]
use tokio::task::JoinHandle;

#[cfg(feature = "hickory-dns")]
use crate::net::ConnectOpts;

#[cfg(feature = "hickory-dns")]
use super::hickory_dns_resolver::DnsResolver as HickoryDnsResolver;

/// Abstract DNS resolver
#[trait_variant::make(Send)]
#[dynosaur::dynosaur(DynDnsResolve)]
pub trait DnsResolve {
    /// Resolves `addr:port` to a list of `SocketAddr`
    async fn resolve(&self, addr: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

// Equivalent to (dyn DnsResolve + Send + Sync)
unsafe impl Send for DynDnsResolve<'_> {}
unsafe impl Sync for DynDnsResolve<'_> {}

#[cfg(feature = "hickory-dns")]
#[derive(Debug)]
pub struct HickoryDnsSystemResolver {
    resolver: ArcSwap<HickoryDnsResolver>,
    #[cfg_attr(any(windows, target_os = "android"), allow(dead_code))]
    connect_opts: ConnectOpts,
    #[cfg_attr(any(windows, target_os = "android"), allow(dead_code))]
    opts: Option<ResolverOpts>,
}

/// Collections of DNS resolver
#[allow(clippy::large_enum_variant)]
pub enum DnsResolver {
    /// System Resolver, which is tokio's builtin resolver
    System,
    /// Trust-DNS's system resolver
    #[cfg(feature = "hickory-dns")]
    HickoryDnsSystem {
        inner: Arc<HickoryDnsSystemResolver>,
        #[cfg(all(feature = "hickory-dns", unix, not(target_os = "android")))]
        abortable: JoinHandle<()>,
    },
    /// Trust-DNS resolver
    #[cfg(feature = "hickory-dns")]
    HickoryDns(HickoryDnsResolver),
    /// Customized Resolver
    Custom(Box<DynDnsResolve<'static>>),
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
            #[cfg(feature = "hickory-dns")]
            DnsResolver::HickoryDnsSystem { .. } => f.write_str("HickoryDnsSystem(..)"),
            #[cfg(feature = "hickory-dns")]
            DnsResolver::HickoryDns(..) => f.write_str("HickoryDns(..)"),
            DnsResolver::Custom(..) => f.write_str("Custom(..)"),
        }
    }
}

#[cfg(feature = "hickory-dns")]
impl Drop for DnsResolver {
    fn drop(&mut self) {
        #[cfg(all(feature = "hickory-dns", unix, not(target_os = "android")))]
        if let DnsResolver::HickoryDnsSystem { ref abortable, .. } = *self {
            abortable.abort();
        }
    }
}

cfg_if! {
    if #[cfg(feature = "hickory-dns")] {
        /// Resolved result
        enum EitherResolved<A, B, C, D> {
            Tokio(A),
            HickoryDnsSystem(B),
            HickoryDns(C),
            Custom(D),
        }

        impl<A, B, C, D> Iterator for EitherResolved<A, B, C, D>
        where
            A: Iterator<Item = SocketAddr>,
            B: Iterator<Item = SocketAddr>,
            C: Iterator<Item = SocketAddr>,
            D: Iterator<Item = SocketAddr>,
        {
            type Item = SocketAddr;

            fn next(&mut self) -> Option<SocketAddr> {
                match *self {
                    EitherResolved::Tokio(ref mut a) => a.next(),
                    EitherResolved::HickoryDnsSystem(ref mut b) => b.next(),
                    EitherResolved::HickoryDns(ref mut c) => c.next(),
                    EitherResolved::Custom(ref mut d) => d.next(),
                }
            }
        }
    } else {
        /// Resolved result
        enum EitherResolved<A, D> {
            Tokio(A),
            Custom(D),
        }

        impl<A, D> Iterator for EitherResolved<A, D>
        where
            A: Iterator<Item = SocketAddr>,
            D: Iterator<Item = SocketAddr>,
        {
            type Item = SocketAddr;

            fn next(&mut self) -> Option<SocketAddr> {
                match *self {
                    EitherResolved::Tokio(ref mut a) => a.next(),
                    EitherResolved::Custom(ref mut d) => d.next(),
                }
            }
        }
    }
}

#[cfg(all(feature = "hickory-dns", unix, not(target_os = "android")))]
async fn hickory_dns_notify_update_dns(resolver: Arc<HickoryDnsSystemResolver>) -> notify::Result<()> {
    use std::{path::Path, time::Duration};

    use log::debug;
    use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher};
    use tokio::{sync::watch, time};

    use super::hickory_dns_resolver::create_resolver;

    const DNS_RESOLV_FILE_PATH: &str = "/etc/resolv.conf";

    if !Path::new(DNS_RESOLV_FILE_PATH).exists() {
        trace!("resolv file {DNS_RESOLV_FILE_PATH} doesn't exist");
        return Ok(());
    }

    let (tx, mut rx) = watch::channel::<Event>(Event::default());

    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(move |ev_result: NotifyResult<Event>| match ev_result {
            Ok(ev) => {
                trace!("received {DNS_RESOLV_FILE_PATH} event {ev:?}");

                if let EventKind::Modify(..) = ev.kind {
                    tx.send(ev).expect("watcher.send");
                }
            }
            Err(err) => {
                error!("watching {DNS_RESOLV_FILE_PATH} error: {err}");
            }
        })?;

    // NOTE: It is an undefined behavior if this file get renamed or removed.
    watcher.watch(Path::new(DNS_RESOLV_FILE_PATH), RecursiveMode::NonRecursive)?;

    // Delayed task
    let mut update_task: Option<JoinHandle<()>> = None;

    while rx.changed().await.is_ok() {
        trace!("received notify {DNS_RESOLV_FILE_PATH} changed");

        // Kill the pending task
        if let Some(t) = update_task.take() {
            t.abort();
        }

        let task = {
            let resolver = resolver.clone();
            tokio::spawn(async move {
                // /etc/resolv.conf may be modified multiple time in 1 second
                // Update once for all those Modify events
                time::sleep(Duration::from_secs(1)).await;

                match create_resolver(None, resolver.opts.clone(), resolver.connect_opts.clone()).await {
                    Ok(r) => {
                        debug!("auto-reload {DNS_RESOLV_FILE_PATH}");

                        resolver.resolver.store(Arc::new(r));
                    }
                    Err(err) => {
                        error!("failed to reload {DNS_RESOLV_FILE_PATH}, error: {err}");
                    }
                }
            })
        };

        update_task = Some(task);
    }

    error!("auto-reload {DNS_RESOLV_FILE_PATH} task exited unexpectedly");

    Ok(())
}

impl DnsResolver {
    /// Use system DNS resolver. Tokio will call `getaddrinfo` in blocking pool.
    pub fn system_resolver() -> DnsResolver {
        DnsResolver::System
    }

    /// Use hickory-dns DNS system resolver (with DNS cache)
    ///
    /// On *nix system, it will try to read configurations from `/etc/resolv.conf`.
    #[cfg(feature = "hickory-dns")]
    pub async fn hickory_dns_system_resolver(
        opts: Option<ResolverOpts>,
        connect_opts: ConnectOpts,
    ) -> io::Result<DnsResolver> {
        use super::hickory_dns_resolver::create_resolver;

        let resolver = create_resolver(None, opts.clone(), connect_opts.clone()).await?;

        let inner = Arc::new(HickoryDnsSystemResolver {
            resolver: ArcSwap::from(Arc::new(resolver)),
            connect_opts,
            opts,
        });

        cfg_if! {
            if #[cfg(all(feature = "hickory-dns", unix, not(target_os = "android")))] {
                let abortable = {
                    let inner = inner.clone();
                    tokio::spawn(async {
                        if let Err(err) = hickory_dns_notify_update_dns(inner).await {
                            error!("failed to watch DNS system configuration changes, error: {}", err);
                        }
                    })
                };

                Ok(DnsResolver::HickoryDnsSystem { inner, abortable })
            } else {
                Ok(DnsResolver::HickoryDnsSystem { inner })
            }
        }
    }

    /// Use hickory-dns DNS resolver (with DNS cache)
    #[cfg(feature = "hickory-dns")]
    pub async fn hickory_resolver(
        dns: ResolverConfig,
        opts: Option<ResolverOpts>,
        connect_opts: ConnectOpts,
    ) -> io::Result<DnsResolver> {
        use super::hickory_dns_resolver::create_resolver;
        Ok(DnsResolver::HickoryDns(
            create_resolver(Some(dns), opts, connect_opts).await?,
        ))
    }

    /// Custom DNS resolver
    pub fn custom_resolver<R>(custom: R) -> DnsResolver
    where
        R: DnsResolve + Send + Sync + 'static,
    {
        DnsResolver::Custom(DynDnsResolve::boxed(custom))
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

        impl Drop for ResolverLogger<'_, '_> {
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
                            #[cfg(feature = "hickory-dns")]
                            DnsResolver::HickoryDnsSystem { .. } | DnsResolver::HickoryDns(..) => {
                                trace!(
                                    "DNS resolved {}:{} with hickory-dns {}s",
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
                        #[cfg(feature = "hickory-dns")]
                        DnsResolver::HickoryDnsSystem { .. } | DnsResolver::HickoryDns(..) => {
                            trace!("DNS resolved {}:{} with hickory-dns", self.addr, self.port);
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
                    let err = Error::new(ErrorKind::Other, format!("dns resolve {addr}:{port} error: {err}"));
                    Err(err)
                }
            },
            #[cfg(feature = "hickory-dns")]
            DnsResolver::HickoryDnsSystem { ref inner, .. } => match inner.resolver.load().lookup_ip(addr).await {
                Ok(lookup_result) => Ok(EitherResolved::HickoryDnsSystem(
                    lookup_result.into_iter().map(move |ip| SocketAddr::new(ip, port)),
                )),
                Err(err) => {
                    let err = Error::new(ErrorKind::Other, format!("dns resolve {addr}:{port} error: {err}"));
                    Err(err)
                }
            },
            #[cfg(feature = "hickory-dns")]
            DnsResolver::HickoryDns(ref resolver) => match resolver.lookup_ip(addr).await {
                Ok(lookup_result) => Ok(EitherResolved::HickoryDns(
                    lookup_result.into_iter().map(move |ip| SocketAddr::new(ip, port)),
                )),
                Err(err) => {
                    let err = Error::new(ErrorKind::Other, format!("dns resolve {addr}:{port} error: {err}"));
                    Err(err)
                }
            },
            DnsResolver::Custom(ref resolver) => match resolver.resolve(addr, port).await {
                Ok(v) => Ok(EitherResolved::Custom(v.into_iter())),
                Err(err) => {
                    let err = Error::new(ErrorKind::Other, format!("dns resolve {addr}:{port} error: {err}"));
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
