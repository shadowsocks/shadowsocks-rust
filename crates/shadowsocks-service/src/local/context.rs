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
    net::ConnectOpts,
    relay::Address,
};
#[cfg(feature = "local-dns")]
use tokio::sync::Mutex;

use crate::net::FlowStat;

use super::acl::AccessControl;

pub struct ServiceContext {
    context: SharedContext,
    connect_opts: ConnectOpts,

    // Access Control
    acl: Option<AccessControl>,

    // Flow statistic report
    flow_stat: Arc<FlowStat>,

    // For DNS relay's ACL domain name reverse lookup -- whether the IP shall be forwarded
    #[cfg(feature = "local-dns")]
    reverse_lookup_cache: Mutex<LruCache<IpAddr, bool>>,
}

impl ServiceContext {
    pub fn new() -> ServiceContext {
        ServiceContext {
            context: Context::new_shared(ServerType::Local),
            connect_opts: ConnectOpts::default(),
            acl: None,
            flow_stat: Arc::new(FlowStat::new()),
            reverse_lookup_cache: Mutex::new(LruCache::with_expiry_duration(Duration::from_secs(3 * 24 * 60 * 60))),
        }
    }

    pub fn context(&self) -> SharedContext {
        self.context.clone()
    }

    pub fn context_ref(&self) -> &Context {
        self.context.as_ref()
    }

    pub fn set_connect_opts(&mut self, connect_opts: ConnectOpts) {
        self.connect_opts = connect_opts;
    }

    pub fn connect_opts_ref(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    pub fn set_acl(&mut self, acl: AccessControl) {
        self.acl = Some(acl);
    }

    pub fn acl(&self) -> Option<&AccessControl> {
        self.acl.as_ref()
    }

    pub fn flow_stat(&self) -> Arc<FlowStat> {
        self.flow_stat.clone()
    }

    pub fn flow_stat_ref(&self) -> &FlowStat {
        self.flow_stat.as_ref()
    }

    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    pub fn dns_resolver(&self) -> &DnsResolver {
        self.context.dns_resolver()
    }

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
}
