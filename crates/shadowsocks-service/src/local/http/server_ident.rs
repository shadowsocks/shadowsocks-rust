//! Server Identifier

use std::sync::Arc;

use hyper::{Body, Client};
use shadowsocks::{config::ServerConfig, context::SharedContext, net::ConnectOpts};

use crate::{
    local::loadbalancing::{BasicServerIdent, ServerIdent, ServerScore},
    net::FlowStat,
};

use super::{connector::ProxyConnector, http_client::ProxyHttpClient};

#[derive(Clone)]
pub struct HttpServerIdent {
    basic: Arc<BasicServerIdent>,
    proxy_client: ProxyHttpClient,
}

impl HttpServerIdent {
    pub fn new(
        context: SharedContext,
        svr_cfg: ServerConfig,
        connect_opts: Arc<ConnectOpts>,
        flow_stat: Arc<FlowStat>,
    ) -> HttpServerIdent {
        let basic = Arc::new(BasicServerIdent::new(svr_cfg));
        let proxy_client =
            Client::builder().build::<_, Body>(ProxyConnector::new(context, basic.clone(), connect_opts, flow_stat));

        HttpServerIdent { basic, proxy_client }
    }

    pub fn proxy_client(&self) -> &ProxyHttpClient {
        &self.proxy_client
    }
}

impl ServerIdent for HttpServerIdent {
    fn server_score<'a>(&'a self) -> &'a ServerScore {
        self.basic.server_score()
    }

    fn server_config<'a>(&'a self) -> &'a ServerConfig {
        self.basic.server_config()
    }
}
