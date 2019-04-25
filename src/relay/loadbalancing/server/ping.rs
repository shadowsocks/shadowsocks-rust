use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{loadbalancing::server::LoadBalancer, socks5::Address, tcprelay::client::ServerClient},
};

use futures::{Future, Stream};
use log::{debug, error};
use tokio::{
    self,
    timer::{Interval, Timeout},
};

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
                // Check every 10 seconds
                Interval::new(Instant::now() + Duration::from_secs(1), Duration::from_secs(10))
                    .for_each(move |_| {
                        let sc = sc.clone();

                        let fut1 = PingBalancer::check_delay(sc.clone(), context.clone(), addr.clone());
                        let fut2 = PingBalancer::check_delay(sc.clone(), context.clone(), addr.clone());
                        let fut3 = PingBalancer::check_delay(sc.clone(), context.clone(), addr.clone());

                        fut1.join3(fut2, fut3).then(move |res| {
                            match res {
                                Ok((d1, d2, d3)) => {
                                    sc.available.store(true, Ordering::Release);
                                    sc.elapsed.store((d1 + d2 + d3) / 3, Ordering::Release);
                                }
                                Err(..) => {
                                    sc.available.store(false, Ordering::Release);
                                }
                            }

                            Ok(())
                        })
                    })
                    .map_err(|_| ()),
            );
        }

        PingBalancer { servers }
    }

    fn check_delay(
        sc: Arc<Server>,
        context: SharedContext,
        addr: Address,
    ) -> impl Future<Item = u64, Error = io::Error> {
        let start = Instant::now();
        let fut = ServerClient::connect(context, addr, sc.config.clone());
        Timeout::new(fut, Duration::from_secs(5)).then(move |res| {
            let elapsed = Instant::now() - start;
            let elapsed = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis()); // Converted to ms
            match res {
                Ok(..) => {
                    // Connected ... record its time
                    debug!(
                        "checked remote server {} connected with {} ms",
                        sc.config.addr(),
                        elapsed
                    );
                    Ok(elapsed)
                }
                Err(err) => {
                    match err.into_inner() {
                        Some(err) => {
                            error!("failed to check server {}, error: {}", sc.config.addr(), err);

                            // NOTE: connection / handshake error, server is down
                            Err(err)
                        }
                        None => {
                            // Timeout
                            error!("checked remote server {} connect timeout", sc.config.addr());

                            // NOTE: timeout is still available, but server is too slow
                            Ok(elapsed)
                        }
                    }
                }
            }
        })
    }
}

impl LoadBalancer for PingBalancer {
    fn pick_server(&mut self) -> Arc<ServerConfig> {
        if self.servers.is_empty() {
            panic!("No server");
        }

        // Choose the best one
        let mut choosen_svr = &self.servers[0];
        let mut found_one = false;

        for svr in &self.servers {
            if svr.available.load(Ordering::Acquire)
                && (!choosen_svr.available.load(Ordering::Acquire)
                    || svr.elapsed.load(Ordering::Acquire) < choosen_svr.elapsed.load(Ordering::Acquire))
            {
                found_one = true;
                choosen_svr = svr;
            }
        }

        if !found_one && !choosen_svr.available.load(Ordering::Acquire) {
            // Just choose one available
            for svr in &self.servers {
                if svr.available.load(Ordering::Acquire) {
                    choosen_svr = svr;
                }
            }

            debug!(
                "cannot find any available servers, picked {} delay {} ms",
                choosen_svr.config.addr(),
                choosen_svr.elapsed.load(Ordering::Acquire)
            );
        } else {
            debug!(
                "choosen the best server {} delay {} ms",
                choosen_svr.config.addr(),
                choosen_svr.elapsed.load(Ordering::Acquire)
            );
        }

        choosen_svr.config.clone()
    }

    fn total(&self) -> usize {
        self.servers.len()
    }
}
