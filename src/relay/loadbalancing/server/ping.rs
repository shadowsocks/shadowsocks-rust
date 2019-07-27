use std::{
    collections::VecDeque,
    fmt, io,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::tcprelay::EncryptedWrite,
    relay::{loadbalancing::server::LoadBalancer, socks5::Address, tcprelay::client::ServerClient},
};

use futures::{Future, Stream};
use log::{debug, error, info};
use tokio::{
    self,
    io::read_exact,
    timer::{Interval, Timeout},
};

struct Server {
    config: Arc<ServerConfig>,
    score: AtomicU64,
}

impl Server {
    fn new(config: ServerConfig) -> Server {
        Server {
            config: Arc::new(config),
            score: AtomicU64::new(0),
        }
    }

    fn score(&self) -> u64 {
        self.score.load(Ordering::Acquire)
    }
}

const MAX_LATENCY_QUEUE_SIZE: usize = 37;

struct ServerLatencyInner {
    latency_queue: VecDeque<u64>,
}

impl ServerLatencyInner {
    fn new() -> ServerLatencyInner {
        ServerLatencyInner {
            latency_queue: VecDeque::with_capacity(MAX_LATENCY_QUEUE_SIZE),
        }
    }

    fn push(&mut self, lat: u64) -> u64 {
        self.latency_queue.push_back(lat);
        if self.latency_queue.len() > MAX_LATENCY_QUEUE_SIZE {
            self.latency_queue.pop_front();
        }

        self.score()
    }

    fn score(&self) -> u64 {
        if self.latency_queue.is_empty() {
            return u64::max_value();
        }

        let sum: u64 = self.latency_queue.iter().sum();
        let avg = sum as f64 / self.latency_queue.len() as f64;
        let s_sum: u64 = self.latency_queue.iter().map(|n| *n * *n).sum();
        let dev = (s_sum as f64 / self.latency_queue.len() as f64 - avg * avg).sqrt();

        let mut v = self
            .latency_queue
            .iter()
            .cloned()
            .filter(|n| *n as f64 >= (avg - 3.0 * dev) && *n as f64 <= (avg + 3.0 * dev))
            .collect::<Vec<u64>>();
        v.sort();

        if v.is_empty() {
            return u64::max_value();
        }

        let mid = v.len() / 2;
        let median = if (v.len() & 1) == 0 {
            (v[mid - 1] + v[mid]) / 2
        } else {
            v[mid]
        };

        debug!(
            "latency queue {:?}, avg {}, dev {}, sorted {:?}, median {}",
            self.latency_queue, avg, dev, v, median
        );

        (((median as f64 * 2.0) + (dev * 1.0)) / 2.0) as u64
    }
}

#[derive(Clone)]
struct ServerLatency {
    inner: Arc<Mutex<ServerLatencyInner>>,
}

impl ServerLatency {
    fn new() -> ServerLatency {
        ServerLatency {
            inner: Arc::new(Mutex::new(ServerLatencyInner::new())),
        }
    }

    fn push(&self, lat: u64) -> u64 {
        let mut inner = self.inner.lock().unwrap();
        inner.push(lat)
    }
}

impl fmt::Debug for ServerLatency {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let inner = self.inner.lock().unwrap();
        write!(f, "ServerLatency {{ latency: {:?} }}", inner.latency_queue)
    }
}

const DEFAULT_CHECK_INTERVAL_SEC: u64 = 6;
const DEFAULT_CHECK_TIMEOUT_SEC: u64 = 5;

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

            let context = context.clone();
            let latency = ServerLatency::new();

            tokio::spawn(
                // Check every DEFAULT_CHECK_INTERVAL_SEC seconds
                Interval::new(
                    Instant::now() + Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC),
                    Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC),
                )
                .for_each(move |_| {
                    let sc = sc.clone();
                    let lat = latency.clone();

                    Inner::check_delay(sc.clone(), context.clone()).then(move |res| {
                        let score = match res {
                            Ok(d) => lat.push(d),
                            Err(..) => lat.push(DEFAULT_CHECK_TIMEOUT_SEC * 2 * 1000), // Penalty
                        };
                        debug!("updated remote server {} (score: {})", sc.config.addr(), score);
                        sc.score.store(score, Ordering::Release);

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

    fn check_delay(sc: Arc<Server>, context: SharedContext) -> impl Future<Item = u64, Error = io::Error> {
        static GET_BODY: &[u8] = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("www.example.com".to_owned(), 80);

        let start = Instant::now();

        // Send HTTP GET and read the first byte
        let fut = ServerClient::connect(context, addr, sc.config.clone()).and_then(|ServerClient { r, w }| {
            w.write_all(GET_BODY)
                .and_then(|(mut w, _)| w.flush())
                .and_then(move |_| read_exact(r, [0u8, 1]))
        });

        Timeout::new(fut, Duration::from_secs(DEFAULT_CHECK_TIMEOUT_SEC)).then(move |res| {
            let elapsed = Instant::now() - start;
            let elapsed = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis()); // Converted to ms
            match res {
                Ok(..) => {
                    // Got the result ... record its time
                    debug!("checked remote server {} latency with {} ms", sc.config.addr(), elapsed);
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
                            debug!(
                                "checked remote server {} latency timeout, elapsed {} ms",
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
                    if svr.score() < choosen_svr.score() {
                        svr_idx = idx;
                    }
                }

                let choosen_svr = &inner.servers[svr_idx];
                debug!(
                    "chosen the best server {} (score: {})",
                    choosen_svr.config.addr(),
                    choosen_svr.score()
                );

                if inner.best_idx() != svr_idx {
                    info!(
                        "switched server from {} (score: {}) to {} (score: {})",
                        inner.best_server().config.addr(),
                        inner.best_server().score(),
                        choosen_svr.config.addr(),
                        choosen_svr.score(),
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
