//! Shadowsocks Local Server Context

use std::sync::Arc;
#[cfg(feature = "local-dns")]
use std::{net::IpAddr, time::Duration};

#[cfg(feature = "local-dns")]
use lru_time_cache::LruCache;
use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
    dns_resolver::DnsResolver,
    net::{AcceptOpts, ConnectOpts},
    relay::Address,
};
#[cfg(feature = "local-dns")]
use tokio::sync::Mutex;
#[cfg(feature = "local-fake-dns")]
use tokio::sync::RwLock;

use crate::{acl::AccessControl, config::SecurityConfig, net::FlowStat};

#[cfg(feature = "local-fake-dns")]
use super::fake_dns::manager::FakeDnsManager;

/// Local Service Context
#[derive(Clone)]
pub struct ServiceContext {
    context: SharedContext,
    connect_opts: ConnectOpts,
    accept_opts: AcceptOpts,

    // Access Control
    acl: Option<Arc<AccessControl>>,

    // Flow statistic report
    flow_stat: Arc<FlowStat>,

    // For DNS relay's ACL domain name reverse lookup -- whether the IP shall be forwarded
    #[cfg(feature = "local-dns")]
    reverse_lookup_cache: Arc<Mutex<LruCache<IpAddr, bool>>>,

    #[cfg(feature = "local-fake-dns")]
    fake_dns_manager: Arc<RwLock<Vec<Arc<FakeDnsManager>>>>,
}

impl Default for ServiceContext {
    fn default() -> Self {
        ServiceContext::new()
    }
}

impl ServiceContext {
    /// Create a new `ServiceContext`
    pub fn new() -> ServiceContext {
        ServiceContext {
            context: Context::new_shared(ServerType::Local),
            connect_opts: ConnectOpts::default(),
            accept_opts: AcceptOpts::default(),
            acl: None,
            flow_stat: Arc::new(FlowStat::new()),
            #[cfg(feature = "local-dns")]
            reverse_lookup_cache: Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(3 * 24 * 60 * 60),
                10240, // XXX: It should be enough for a normal user.
            ))),
            #[cfg(feature = "local-fake-dns")]
            fake_dns_manager: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get cloned `shadowsocks` Context
    pub fn context(&self) -> SharedContext {
        self.context.clone()
    }

    /// Get `shadowsocks` Context reference
    pub fn context_ref(&self) -> &Context {
        self.context.as_ref()
    }

    /// Set `ConnectOpts`
    pub fn set_connect_opts(&mut self, connect_opts: ConnectOpts) {
        self.connect_opts = connect_opts;
    }

    /// Get `ConnectOpts` reference
    pub fn connect_opts_ref(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    /// Set `AcceptOpts`
    pub fn set_accept_opts(&mut self, accept_opts: AcceptOpts) {
        self.accept_opts = accept_opts;
    }

    /// Get `AcceptOpts` cloned
    pub fn accept_opts(&self) -> AcceptOpts {
        self.accept_opts.clone()
    }

    /// Set Access Control List
    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        self.acl = Some(acl);
    }

    /// Get Access Control List reference
    pub fn acl(&self) -> Option<&AccessControl> {
        self.acl.as_deref()
    }

    /// Get cloned flow statistic
    pub fn flow_stat(&self) -> Arc<FlowStat> {
        self.flow_stat.clone()
    }

    /// Get flow statistic reference
    pub fn flow_stat_ref(&self) -> &FlowStat {
        self.flow_stat.as_ref()
    }

    /// Set customized DNS resolver
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    /// Get reference of DNS resolver
    pub fn dns_resolver(&self) -> &DnsResolver {
        self.context.dns_resolver()
    }

    /// Check if target should be bypassed
    pub async fn check_target_bypassed(&self, addr: &Address) -> bool {
        match self.acl {
            None => false,
            Some(ref acl) => {
                #[cfg(feature = "local-dns")]
                {
                    if let Address::SocketAddress(ref saddr) = addr {
                        // do the reverse lookup in our local cache
                        let mut reverse_lookup_cache = self.reverse_lookup_cache.lock().await;
                        // if a qname is found
                        if let Some(forward) = reverse_lookup_cache.get(&saddr.ip()) {
                            return !*forward;
                        }
                    }
                }

                acl.check_target_bypassed(&self.context, addr).await
            }
        }
    }

    /// Add a record to the reverse lookup cache
    #[cfg(feature = "local-dns")]
    pub async fn add_to_reverse_lookup_cache(&self, addr: IpAddr, forward: bool) {
        let is_exception = forward
            != match self.acl {
                // Proxy everything by default
                None => true,
                Some(ref a) => a.check_ip_in_proxy_list(&addr),
            };
        let mut reverse_lookup_cache = self.reverse_lookup_cache.lock().await;
        match reverse_lookup_cache.get_mut(&addr) {
            Some(value) => {
                if is_exception {
                    *value = forward;
                } else {
                    // we do not need to remember the entry if it is already matched correctly
                    reverse_lookup_cache.remove(&addr);
                }
            }
            None => {
                if is_exception {
                    reverse_lookup_cache.insert(addr, forward);
                }
            }
        }
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ipv6_first on a shared context");
        context.set_ipv6_first(ipv6_first);
    }

    /// Set security config
    pub fn set_security_config(&mut self, security: &SecurityConfig) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set security on a shared context");
        context.set_replay_attack_policy(security.replay_attack.policy);
    }

    /// Set Fake DNS manager
    #[cfg(feature = "local-fake-dns")]
    pub async fn add_fake_dns_manager(&self, manager: Arc<FakeDnsManager>) {
        let mut managers = self.fake_dns_manager.write().await;
        managers.push(manager);
    }

    /// Fake DNS maps IP to Domain
    #[cfg(feature = "local-fake-dns")]
    pub async fn try_map_fake_address(&self, addr: &Address) -> Option<Address> {
        let socket_addr = match addr {
            Address::DomainNameAddress(..) => return None,
            Address::SocketAddress(socket_addr) => socket_addr,
        };
        let ip_addr = socket_addr.ip();

        for mgr in self.fake_dns_manager.read().await.iter() {
            if let Ok(Some(name)) = mgr.map_ip_domain(ip_addr).await {
                let new_addr = Address::DomainNameAddress(name.to_string(), socket_addr.port());
                log::trace!("fakedns mapped {} -> {}", addr, new_addr);
                return Some(new_addr);
            }
        }

        None
    }
}
