//! Shadowsocks Local Server Context

use std::{net::SocketAddr, sync::Arc};

use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
    dns_resolver::DnsResolver,
    net::ConnectOpts,
    relay::Address,
};

use crate::{acl::AccessControl, config::SecurityConfig, net::FlowStat};

/// Server Service Context
#[derive(Clone)]
pub struct ServiceContext {
    context: SharedContext,
    connect_opts: ConnectOpts,

    // Access Control
    acl: Option<Arc<AccessControl>>,

    // Flow statistic report
    flow_stat: Arc<FlowStat>,
}

impl Default for ServiceContext {
    fn default() -> Self {
        Self {
            context: Context::new_shared(ServerType::Server),
            connect_opts: ConnectOpts::default(),
            acl: None,
            flow_stat: Arc::new(FlowStat::new()),
        }
    }
}

impl ServiceContext {
    /// Create a new `ServiceContext`
    pub fn new() -> Self {
        Self::default()
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
    pub async fn check_outbound_blocked(&self, addr: &Address) -> bool {
        match self.acl {
            None => false,
            Some(ref acl) => acl.check_outbound_blocked(&self.context, addr).await,
        }
    }

    /// Check if client should be blocked
    pub fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        match self.acl {
            None => false,
            Some(ref acl) => acl.check_client_blocked(addr),
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
}
