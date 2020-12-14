//! Server Identifier

use std::sync::Arc;

use hyper::{Body, Client};
use shadowsocks::config::ServerConfig;

use crate::local::{
    context::ServiceContext,
    loadbalancing::{BasicServerIdent, ServerIdent, ServerScore},
};

use super::{connector::ProxyConnector, http_client::ProxyHttpClient};

#[derive(Clone)]
pub struct HttpServerIdent {
    basic: Arc<BasicServerIdent>,
    proxy_client: ProxyHttpClient,
}

impl HttpServerIdent {
    pub fn new(context: Arc<ServiceContext>, svr_cfg: ServerConfig) -> HttpServerIdent {
        let basic = Arc::new(BasicServerIdent::new(svr_cfg));
        let proxy_client = Client::builder().build::<_, Body>(ProxyConnector::new(context, basic.clone()));

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
