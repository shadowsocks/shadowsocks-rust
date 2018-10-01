//! Load balancer using round robin strategy

use std::sync::Arc;

use config::{Config, ServerConfig};
use relay::loadbalancing::server::LoadBalancer;

#[derive(Clone)]
pub struct RoundRobin {
    servers: Vec<Arc<ServerConfig>>,
    index: usize,
}

impl RoundRobin {
    pub fn new(config: &Config) -> RoundRobin {
        RoundRobin {
            servers: config.server.iter().map(|s| Arc::new(s.clone())).collect(),
            index: 0usize,
        }
    }
}

impl LoadBalancer for RoundRobin {
    fn pick_server(&mut self) -> Arc<ServerConfig> {
        let server = &self.servers;

        if server.is_empty() {
            panic!("No server");
        }

        let s = &server[self.index];
        self.index = (self.index + 1) % server.len();
        s.clone()
    }

    fn total(&self) -> usize {
        self.servers.len()
    }
}
