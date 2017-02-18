//! Load balancer for picking servers

use std::rc::Rc;

pub use self::roundrobin::RoundRobin;

use config::ServerConfig;

pub mod roundrobin;

pub trait LoadBalancer {
    fn pick_server(&mut self) -> Rc<ServerConfig>;
    fn total(&self) -> usize;
}
