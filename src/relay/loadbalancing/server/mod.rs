//! Load balancer for picking servers

use std::sync::Arc;

pub use self::ping::PingBalancer;
pub use self::roundrobin::RoundRobin;

use crate::config::ServerConfig;

pub mod ping;
pub mod roundrobin;

pub trait LoadBalancer {
    fn pick_server(&mut self) -> Arc<ServerConfig>;
    fn total(&self) -> usize;
}
