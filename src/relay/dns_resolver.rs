//! Asynchronous DNS resolver

use std::io::{self, ErrorKind};
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::Future;
use spin::Mutex;
use tokio::runtime::current_thread::Runtime;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::AsyncResolver;

use config::Config;

// Taken from
// bluejekyll/trust-dns/resolver/examples/global_resolver.rs
lazy_static! {
    static ref GLOBAL_DNS_ADDRESS: Mutex<Option<ResolverConfig>> = Mutex::new(None);

    // First we need to setup the global Resolver
    static ref GLOBAL_DNS_RESOLVER: AsyncResolver = init_resolver();
}

/// Set address for global DNS resolver
/// Must be called before servers are actually run
pub fn set_dns_config(addr: ResolverConfig) {
    *(&mut *GLOBAL_DNS_ADDRESS.lock()) = Some(addr);
}

fn get_dns_address() -> Option<ResolverConfig> {
    GLOBAL_DNS_ADDRESS.lock().clone()
}

fn init_resolver() -> AsyncResolver {
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;

    // We'll be using this condvar to get the Resolver from the thread...
    let pair = Arc::new((Mutex::new(None::<AsyncResolver>), Condvar::new()));
    let pair2 = pair.clone();

    // Spawn the runtime to a new thread...
    //
    // This thread will manage the actual resolution runtime
    thread::spawn(move || {
                      // A runtime for this new thread
                      let mut runtime = Runtime::new().expect("failed to launch Runtime");

                      // our platform independent future, result, see next blocks
                      let (resolver, bg) = {
                          // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
                          #[cfg(any(unix, windows))]
                          {
                              if let Some(conf) = get_dns_address() {
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

                              if let Some(conf) = get_dns_address() {
                                  AsyncResolver::new(conf, ResolverOpts::default())
                              } else {
                                  // Get a new resolver with the google nameservers as the upstream recursive resolvers
                                  AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default())
                              }
                          }
                      };

                      let &(ref lock, ref cvar) = &*pair2;
                      let mut started = lock.lock().unwrap();
                      *started = Some(resolver);
                      cvar.notify_one();
                      drop(started);

                      runtime.block_on(bg).expect("Failed to create DNS resolver");
                  });

    // Wait for the thread to start up.
    let &(ref lock, ref cvar) = &*pair;
    let mut resolver = lock.lock().unwrap();
    while resolver.is_none() {
        resolver = cvar.wait(resolver).unwrap();
    }

    // take the started resolver
    let resolver = mem::replace(&mut *resolver, None);

    // set the global resolver
    resolver.expect("resolver should not be none")
}

fn inner_resolve(config: Arc<Config>,
                 addr: &str,
                 port: u16,
                 check_forbidden: bool)
                 -> impl Future<Item = Vec<SocketAddr>, Error = io::Error> + Send {
    let owned_addr = addr.to_owned();
    let owned_addr2 = owned_addr.clone();

    GLOBAL_DNS_RESOLVER.lookup_ip(addr)
                       .map_err(move |err| {
                                    error!("Failed to resolve {}, err: {}", owned_addr2, err);
                                    io::Error::new(io::ErrorKind::Other, "dns resolve error")
                                })
                       .and_then(move |lookup_result| {
                                     let mut vaddr = Vec::new();
                                     for ip in lookup_result.iter() {
                                         if check_forbidden {
                                             let forbidden_ip = &config.forbidden_ip;
                                             if forbidden_ip.contains(&ip) {
                                                 debug!("Resolved {} => {}, which is skipped by forbidden_ip",
                                                        owned_addr, ip);
                                                 continue;
                                             }
                                         }
                                         vaddr.push(SocketAddr::new(ip, port));
                                     }

                                     if vaddr.is_empty() {
                                         let err = io::Error::new(ErrorKind::Other,
                                                       format!("resolved {} to empty address, all IPs are filtered",
                                                               owned_addr));
                                         Err(err)
                                     } else {
                                         debug!("Resolved {} => {:?}", owned_addr, vaddr);
                                         Ok(vaddr)
                                     }
                                 })
}

/// Resolve address to IP
pub fn resolve(config: Arc<Config>,
               addr: &str,
               port: u16,
               check_forbidden: bool)
               -> impl Future<Item = Vec<SocketAddr>, Error = io::Error> + Send {
    inner_resolve(config, addr, port, check_forbidden)
}
