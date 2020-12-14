//! Shadowsocks Local Service Context

use std::sync::Arc;

use shadowsocks::{context::SharedContext, net::ConnectOpts};

use crate::{local::acl::AccessControl, net::FlowStat};

pub struct LocalServiceContext {
    context: SharedContext,
    connect_opts: ConnectOpts,
    flow_stat: Arc<FlowStat>,
    acl: Option<AccessControl>,
}
