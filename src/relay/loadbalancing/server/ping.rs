use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
use log::{debug, error, info};
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

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    fn delay(&self) -> u64 {
        self.elapsed.load(Ordering::Acquire)
    }
}

const DEFAULT_CHECK_INTERVAL_SEC: u64 = 10;

struct Inner {
    servers: Vec<Arc<Server>>,
    best_idx: AtomicUsize,
}

impl Inner {
    fn new(context: SharedContext) -> Inner {
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
                Interval::new(
                    Instant::now() + Duration::from_secs(1),
                    Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC),
                )
                .for_each(move |_| {
                    let sc = sc.clone();

                    let fut1 = Inner::check_delay(sc.clone(), context.clone(), addr.clone());
                    let fut2 = Inner::check_delay(sc.clone(), context.clone(), addr.clone());
                    let fut3 = Inner::check_delay(sc.clone(), context.clone(), addr.clone());

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

        Inner {
            servers,
            best_idx: AtomicUsize::new(0),
        }
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
                            error!(
                                "checked remote server {} connect timeout, elapsed {} ms",
                                sc.config.addr(),
                                elapsed
                            );

                            // NOTE: timeout is still available, but server is too slow
                            Ok(elapsed)
                        }
                    }
                }
            }
        })
    }

    fn best_idx(&self) -> usize {
        self.best_idx.load(Ordering::Acquire)
    }

    fn set_best_idx(&self, idx: usize) {
        self.best_idx.store(idx, Ordering::Release)
    }

    fn best_server(&self) -> &Arc<Server> {
        &self.servers[self.best_idx()]
    }
}

#[derive(Clone)]
pub struct PingBalancer {
    inner: Arc<Inner>,
}

impl PingBalancer {
    pub fn new(context: SharedContext) -> PingBalancer {
        let inner = Arc::new(Inner::new(context));

        let inner_cloned = inner.clone();
        tokio::spawn(
            Interval::new(
                Instant::now() + Duration::from_secs(2),
                Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC),
            )
            .for_each(move |_| {
                let inner = inner_cloned.clone();

                if inner.servers.is_empty() {
                    panic!("No server");
                }

                // Choose the best one
                let mut svr_idx = 0;

                for (idx, svr) in inner.servers.iter().enumerate() {
                    let choosen_svr = &inner.servers[svr_idx];
                    if svr.is_available() && (!choosen_svr.is_available() || svr.delay() < choosen_svr.delay()) {
                        svr_idx = idx;
                    }
                }

                let choosen_svr = &inner.servers[svr_idx];
                if svr_idx == 0 && !choosen_svr.is_available() {
                    // Cannot find any usable servers, use the first one (svr_idx = 0)
                    error!(
                        "cannot find any usable servers, picked {} (delay: {} ms)",
                        choosen_svr.config.addr(),
                        choosen_svr.delay()
                    );
                } else {
                    debug!(
                        "chosen the best server {} (delay: {} ms)",
                        choosen_svr.config.addr(),
                        choosen_svr.delay()
                    );
                }

                if inner.best_idx() != svr_idx {
                    info!(
                        "switched server from {} (delay: {} ms) to {} (delay: {} ms)",
                        inner.best_server().config.addr(),
                        inner.best_server().delay(),
                        choosen_svr.config.addr(),
                        choosen_svr.delay(),
                    );
                }

                inner.set_best_idx(svr_idx);

                Ok(())
            })
            .map_err(|_| ()),
        );

        PingBalancer { inner }
    }
}

impl LoadBalancer for PingBalancer {
    fn pick_server(&mut self) -> Arc<ServerConfig> {
        if self.inner.servers.is_empty() {
            panic!("no server in configuration");
        }
        self.inner.best_server().config.clone()
    }

    fn total(&self) -> usize {
        self.inner.servers.len()
    }
}
