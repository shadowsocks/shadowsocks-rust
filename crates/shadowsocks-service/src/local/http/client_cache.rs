//! Cached HTTP client for remote server

use std::{sync::Arc, time::Duration};

use hyper::{Body, Client};
use lfu_cache::TimedLfuCache;
use shadowsocks::config::ServerAddr;
use tokio::sync::Mutex;

use crate::local::{context::ServiceContext, loadbalancing::ServerIdent};

use super::{connector::ProxyConnector, http_client::ProxyHttpClient};

/// Cached HTTP client for remote servers
pub struct ProxyClientCache {
    context: Arc<ServiceContext>,
    cache: Mutex<TimedLfuCache<ServerAddr, ProxyHttpClient>>,
}

impl ProxyClientCache {
    pub fn new(context: Arc<ServiceContext>) -> ProxyClientCache {
        ProxyClientCache {
            context,
            cache: Mutex::new(TimedLfuCache::with_capacity_and_expiration(5, Duration::from_secs(60))),
        }
    }

    pub async fn get_connected(&self, server: &Arc<ServerIdent>) -> ProxyHttpClient {
        let server_config = server.server_config();

        let mut cache = self.cache.lock().await;
        if let Some(client) = cache.get(server_config.addr()) {
            return client.clone();
        }

        // Create a new client
        let client = Client::builder()
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .build::<_, Body>(ProxyConnector::new(self.context.clone(), server.clone()));
        cache.insert(server_config.addr().clone(), client.clone());

        client
    }
}
