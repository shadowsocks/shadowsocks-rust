use std::{
    collections::VecDeque,
    fmt,
    io,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
        Mutex,
    },
};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{loadbalancing::server::LoadBalancer, socks5::Address, tcprelay::client::ServerClient},
};

use log::{debug, info};
use tokio::{
    self,
    io::{AsyncReadExt, AsyncWriteExt},
    time::{self, Duration, Instant},
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

        let mut v = self.latency_queue.iter().cloned().collect::<Vec<u64>>();
        v.sort();

        let mid = v.len() / 2;
        if (v.len() & 1) == 0 {
            (v[mid - 1] + v[mid]) / 2
        } else {
            v[mid]
        }
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
                async move {
                    // Wait until the server is ready (plugins are started)
                    time::delay_for(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC)).await;

                    let mut interval = time::interval(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC));

                    while context.server_running() {
                        interval.tick().await;
                        let score = match Inner::check_delay(sc.clone(), context.clone()).await {
                            Ok(d) => latency.push(d),
                            Err(..) => latency.push(DEFAULT_CHECK_TIMEOUT_SEC * 2 * 1000), // Penalty
                        };
                        debug!("updated remote server {} (score: {})", sc.config.addr(), score);
                        sc.score.store(score, Ordering::Release);
                    }
                },
            );
        }

        Inner {
            servers,
            best_idx: AtomicUsize::new(0),
        }
    }

    async fn check_request(sc: Arc<ServerConfig>, context: SharedContext) -> io::Result<()> {
        static GET_BODY: &[u8] =
            b"GET /generate_204 HTTP/1.1\r\nHost: dl.google.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("dl.google.com".to_owned(), 80);

        let ServerClient { mut stream } = ServerClient::connect(context, &addr, sc).await?;
        stream.write_all(GET_BODY).await?;
        stream.flush().await?;
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;

        Ok(())
    }

    async fn check_delay(sc: Arc<Server>, context: SharedContext) -> io::Result<u64> {
        let start = Instant::now();

        // Send HTTP GET and read the first byte
        let timeout = Duration::from_secs(DEFAULT_CHECK_TIMEOUT_SEC);
        let res = time::timeout(timeout, Inner::check_request(sc.config.clone(), context.clone())).await;

        let elapsed = Instant::now() - start;
        let elapsed = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis()); // Converted to ms
        match res {
            Ok(Ok(..)) => {
                // Got the result ... record its time
                debug!("checked remote server {} latency with {} ms", sc.config.addr(), elapsed);
                Ok(elapsed)
            }
            Ok(Err(err)) => {
                debug!("failed to check server {}, error: {}", sc.config.addr(), err);

                // NOTE: connection / handshake error, server is down
                Err(err)
            }
            Err(..) => {
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
        let inner = Arc::new(Inner::new(context.clone()));

        if inner.servers.len() > 1 {
            let cloned_inner = inner.clone();
            tokio::spawn(async move {
                let inner = cloned_inner;

                // Wait until the server is ready (plugins are started)
                time::delay_for(Duration::from_secs(2)).await;

                let mut interval = time::interval(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC));

                while context.server_running() {
                    interval.tick().await;

                    assert!(!inner.servers.is_empty());

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
                }
            });
        }

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
