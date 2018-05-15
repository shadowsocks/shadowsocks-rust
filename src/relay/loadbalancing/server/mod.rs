//! Load balancer for picking servers

use std::sync::Arc;

pub use self::roundrobin::RoundRobin;

use config::ServerConfig;

pub mod roundrobin;

pub trait LoadBalancer {
    fn pick_server(&mut self) -> Arc<ServerConfig>;
    fn total(&self) -> usize;
}
