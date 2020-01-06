//! Load balancer for picking servers

use std::sync::Arc;

pub use self::ping::{PingBalancer, Server as PingServer, ServerType as PingServerType};

pub mod ping;

pub trait LoadBalancer {
    type Server;

    // Pick a server for connecting
    fn pick_server(&mut self) -> Arc<Self::Server>;

    // Total servers this balancer is holding
    fn total(&self) -> usize;
}
