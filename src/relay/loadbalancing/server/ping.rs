use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    config::ServerConfig, context::SharedContext, relay::loadbalancing::server::LoadBalancer, relay::socks5::Address,
    relay::tcprelay::client::ServerClient,
};

use futures::{Future, Stream};
use log::{debug, error, trace};
use rand;
use tokio;
use tokio::timer::{Interval, Timeout};

struct Server {
    config: Arc<ServerConfig>,
    elapsed: AtomicU64,
    available: AtomicBool,
}

impl Server {
    fn new(config: ServerConfig) -> Server {
        Server {
            config: Arc::new(config),
            elapsed: AtomicU64::new(0),
            available: AtomicBool::new(true),
        }
    }
}

#[derive(Clone)]
pub struct PingBalancer {
    servers: Vec<Arc<Server>>,
}

impl PingBalancer {
    pub fn new(context: SharedContext) -> PingBalancer {
        let config = context.config();

        if config.server.is_empty() {
            panic!("no servers");
        }

        let check_required = config.server.len() > 1;

        let mut servers = Vec::new();
        for svr in &config.server {
            let sc = Arc::new(Server::new(svr.clone()));
            servers.push(sc.clone());

            if !check_required {
                continue;
            }

            let addr = Address::DomainNameAddress("www.example.com".to_owned(), 80);
            let context = context.clone();

            tokio::spawn(
                // Check every 60 seconds
                Interval::new_interval(Duration::from_secs(3))
                    .for_each(move |_| {
                        let sc = sc.clone();
                        let start = Instant::now();
                        let fut = ServerClient::connect(context.clone(), addr.clone(), sc.config.clone());
                        Timeout::new(fut, Duration::from_secs(2)).then(move |res| {
                            let elapsed = Instant::now() - start;
                            let elapsed = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis()); // Converted to ms
                            match res {
                                Ok(..) => {
                                    // Connected ... record its time
                                    trace!(
                                        "checked remote server {} connected with {} ms",
                                        sc.config.addr(),
                                        elapsed
                                    );
                                    sc.available.store(true, Ordering::Release);
                                }
                                Err(err) => {
                                    match err.into_inner() {
                                        Some(err) => {
                                            error!("failed to check server {}, error: {}", sc.config.addr(), err);
                                        }
                                        None => {
                                            // Timeout
                                            error!("checked remote server {} connect timeout", sc.config.addr());
                                        }
                                    }
                                    sc.available.store(false, Ordering::Release);
                                }
                            }
                            // Set elapsed anyway
                            sc.elapsed.store(elapsed, Ordering::Release);

                            Ok(())
                        })
                    })
                    .map_err(|_| ()),
            );
        }

        PingBalancer { servers }
    }
}

impl LoadBalancer for PingBalancer {
    fn pick_server(&mut self) -> Arc<ServerConfig> {
        if self.servers.is_empty() {
            panic!("No server");
        }

        let mut total = 0u64;
        for svr in &self.servers {
            if svr.available.load(Ordering::Acquire) {
                total += svr.elapsed.load(Ordering::Acquire);
            } else {
                debug!("server {} is blocked for unavailable", svr.config.addr());
            }
        }

        if total != 0 {
            let ridx = rand::random::<u64>() % total;
            let mut acc = 0u64;
            for svr in &self.servers {
                if svr.available.load(Ordering::Acquire) {
                    acc += svr.elapsed.load(Ordering::Acquire);
                    if acc >= ridx {
                        return svr.config.clone();
                    }
                } else {
                    debug!("server {} is blocked for unavailable", svr.config.addr());
                }
            }
        }

        // FALLBACK! Choose nothing
        for svr in &self.servers {
            if svr.available.load(Ordering::Acquire) {
                return svr.config.clone();
            }
        }

        // ALL UNAVAILABLE!
        error!("all servers are unavailable!");
        self.servers[0].config.clone()
    }

    fn total(&self) -> usize {
        self.servers.len()
    }
}
