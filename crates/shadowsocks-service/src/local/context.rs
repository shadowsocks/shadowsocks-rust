//! Shadowsocks Local Server Context

use std::sync::Arc;

use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
    dns_resolver::DnsResolver,
    net::ConnectOpts,
    relay::Address,
};

use crate::net::FlowStat;

use super::acl::AccessControl;

pub struct ServiceContext {
    context: SharedContext,
    connect_opts: ConnectOpts,
    acl: Option<AccessControl>,
    flow_stat: Arc<FlowStat>,
}

impl ServiceContext {
    pub fn new() -> ServiceContext {
        ServiceContext {
            context: Context::new_shared(ServerType::Local),
            connect_opts: ConnectOpts::default(),
            acl: None,
            flow_stat: Arc::new(FlowStat::new()),
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

    pub fn connect_opts(&self) -> &ConnectOpts {
        &self.connect_opts
    }

    pub fn set_acl(&mut self, acl: AccessControl) {
        self.acl = Some(acl);
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

    pub async fn check_target_bypassed(&self, addr: &Address) -> bool {
        match self.acl {
            None => false,
            Some(ref acl) => acl.check_target_bypassed(&self.context, addr).await,
        }
    }
}
