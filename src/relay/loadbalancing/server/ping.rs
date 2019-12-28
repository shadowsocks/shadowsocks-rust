use std::{
    collections::VecDeque,
    fmt,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
        Mutex,
    },
    time::{Duration, Instant},
};

use crate::{
    config::ServerConfig,
    context::{Context, SharedContext},
    relay::{
        loadbalancing::server::LoadBalancer,
        socks5::Address,
        tcprelay::client::ServerClient as TcpServerClient,
        udprelay::client::ServerClient as UdpServerClient,
    },
};

use log::{debug, info};
use tokio::{
    self,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Barrier,
    time,
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

#[derive(Debug, Copy, Clone)]
enum Score {
    Latency(u64),
    Errored,
}

struct ServerLatencyInner {
    latency_queue: VecDeque<Score>,
}

impl ServerLatencyInner {
    fn new() -> ServerLatencyInner {
        ServerLatencyInner {
            latency_queue: VecDeque::with_capacity(MAX_LATENCY_QUEUE_SIZE),
        }
    }

    fn push(&mut self, lat: Score) -> u64 {
        self.latency_queue.push_back(lat);
        if self.latency_queue.len() > MAX_LATENCY_QUEUE_SIZE {
            self.latency_queue.pop_front();
        }

        self.score()
    }

    fn score(&self) -> u64 {
        if self.latency_queue.is_empty() {
            // Never checked, assume it is the worst of all
            return 2 * 1000;
        }

        // 1. Mid Latency
        // 2. Proportion of Errors
        let mut vec_lat = Vec::with_capacity(self.latency_queue.len());
        let mut acc_err = 0;
        for lat in &self.latency_queue {
            match lat {
                Score::Latency(l) => vec_lat.push(l),
                Score::Errored => acc_err += 1,
            }
        }

        let max_lat = DEFAULT_CHECK_TIMEOUT_SEC * 1000;

        // Find the mid of latencies
        let mid_lat = if vec_lat.is_empty() {
            // The whole array are errors
            max_lat
        } else {
            vec_lat.sort();
            let mid = vec_lat.len() / 2;
            if vec_lat.len() % 2 == 0 {
                (vec_lat[mid] + vec_lat[mid - 1]) / 2
            } else {
                *vec_lat[mid]
            }
        };

        // Score = norm_lat + prop_err
        //
        // 1. The lower latency, the better
        // 2. The lower errored count, the better
        let norm_lat = mid_lat as f64 / max_lat as f64;
        let prop_err = acc_err as f64 / self.latency_queue.len() as f64;

        ((norm_lat + prop_err) * 1000.0) as u64
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

    fn push(&self, lat: Score) -> u64 {
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
const DEFAULT_CHECK_TIMEOUT_SEC: u64 = 2; // Latency shouldn't greater than 2 secs, that's too long

struct Inner {
    servers: Vec<Arc<Server>>,
    best_idx: AtomicUsize,
}

impl Inner {
    async fn new(context: SharedContext, server_type: ServerType) -> Inner {
        let config = context.config();
        assert!(!config.server.is_empty());

        // Load balancer is only required in multi-server configuration
        let check_required = config.server.len() > 1;

        // Wait for all ping tasks to be started
        let barrier = Arc::new(Barrier::new(config.server.len() + 1));

        let mut servers = Vec::new();
        for svr in &config.server {
            let sc = Arc::new(Server::new(svr.clone()));
            servers.push(sc.clone());

            if !check_required {
                continue;
            }

            let context = context.clone();
            let latency = ServerLatency::new();
            let barrier = barrier.clone();

            // Check every DEFAULT_CHECK_INTERVAL_SEC seconds
            tokio::spawn(async move {
                debug!(
                    "{:?} server {} latency ping task initializing",
                    server_type,
                    sc.config.addr()
                );

                // Quickly collect some latency data
                //
                // Maximum wait duration: DEFAULT_CHECK_TIMEOUT_SEC
                Inner::check_update_score(&latency, &*sc, &*context, server_type).await;

                // Wait until all the other tasks are finished initializing
                barrier.wait().await;
                drop(barrier);

                debug!(
                    "{:?} server {} latency ping task started",
                    server_type,
                    sc.config.addr()
                );

                while context.server_running() {
                    // First round may be failed, plugins are started asynchronously
                    Inner::check_update_score(&latency, &*sc, &*context, server_type).await;

                    time::delay_for(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC)).await;
                }

                debug!(
                    "{:?} server {} latency ping task stopped",
                    server_type,
                    sc.config.addr()
                );
            });
        }

        if check_required {
            barrier.wait().await;
        }

        Inner {
            servers,
            best_idx: AtomicUsize::new(0),
        }
    }

    async fn check_update_score(latency: &ServerLatency, sc: &Server, context: &Context, server_type: ServerType) {
        let score = match Inner::check_delay(&*sc, &*context, server_type).await {
            Ok(d) => latency.push(Score::Latency(d)),
            Err(..) => latency.push(Score::Errored), // Penalty
        };
        debug!(
            "updated remote {:?} server {} (score: {})",
            server_type,
            sc.config.addr(),
            score
        );
        sc.score.store(score, Ordering::Release);
    }

    async fn check_request_tcp(sc: Arc<ServerConfig>, context: &Context) -> io::Result<()> {
        static GET_BODY: &[u8] =
            b"GET /generate_204 HTTP/1.1\r\nHost: dl.google.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("dl.google.com".to_owned(), 80);

        let TcpServerClient { mut stream } = TcpServerClient::connect(context, &addr, sc).await?;
        stream.write_all(GET_BODY).await?;
        stream.flush().await?;
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;

        Ok(())
    }

    async fn check_request_udp(sc: Arc<ServerConfig>, context: &Context) -> io::Result<()> {
        static DNS_QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

        let addr = Address::SocketAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));

        let mut client = UdpServerClient::new(sc).await?;
        client.send_to(context, &addr, DNS_QUERY).await?;
        let _ = client.recv_from(context).await?;

        Ok(())
    }

    async fn check_request(sc: Arc<ServerConfig>, context: &Context, server_type: ServerType) -> io::Result<()> {
        match server_type {
            ServerType::Tcp => Inner::check_request_tcp(sc, context).await,
            ServerType::Udp => Inner::check_request_udp(sc, context).await,
        }
    }

    async fn check_delay(sc: &Server, context: &Context, server_type: ServerType) -> io::Result<u64> {
        let start = Instant::now();

        // Send HTTP GET and read the first byte
        let timeout = Duration::from_secs(DEFAULT_CHECK_TIMEOUT_SEC);
        let res = time::timeout(timeout, Inner::check_request(sc.config.clone(), context, server_type)).await;

        let elapsed = Instant::now() - start;
        let elapsed = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis()); // Converted to ms
        match res {
            Ok(Ok(..)) => {
                // Got the result ... record its time
                debug!(
                    "checked remote {:?} server {} latency with {} ms",
                    server_type,
                    sc.config.addr(),
                    elapsed
                );
                Ok(elapsed)
            }
            Ok(Err(err)) => {
                debug!(
                    "failed to check {:?} server {}, error: {}",
                    server_type,
                    sc.config.addr(),
                    err
                );

                // NOTE: connection / handshake error, server is down
                Err(err)
            }
            Err(..) => {
                // Timeout
                debug!(
                    "checked remote {:?} server {} latency timeout, elapsed {} ms",
                    server_type,
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

#[derive(Debug, Clone, Copy)]
pub enum ServerType {
    Tcp,
    Udp,
}

/// Load balancer based on pinging latencies of all servers
#[derive(Clone)]
pub struct PingBalancer {
    inner: Arc<Inner>,
}

impl PingBalancer {
    /// Create a PingBalancer
    pub async fn new(context: SharedContext, server_type: ServerType) -> PingBalancer {
        // Wait until all tasks are started
        let inner = Arc::new(Inner::new(context.clone(), server_type).await);

        if inner.servers.len() > 1 {
            let barrier = Arc::new(Barrier::new(2));

            let cloned_inner = inner.clone();
            let cloned_barrier = barrier.clone();
            tokio::spawn(async move {
                let inner = cloned_inner;
                assert!(!inner.servers.is_empty());

                let mut opt_barrier = Some(cloned_barrier);

                while context.server_running() {
                    // Choose the best one
                    let mut svr_idx = 0;

                    for (idx, svr) in inner.servers.iter().enumerate() {
                        let choosen_svr = &inner.servers[svr_idx];
                        if svr.score() < choosen_svr.score() {
                            svr_idx = idx;
                        }
                    }

                    let choosen_svr = &inner.servers[svr_idx];
                    if choosen_svr.score() != inner.servers[inner.best_idx()].score() {
                        if opt_barrier.is_none() {
                            info!(
                                "switched {:?} server from {} (score: {}) to {} (score: {})",
                                server_type,
                                inner.best_server().config.addr(),
                                inner.best_server().score(),
                                choosen_svr.config.addr(),
                                choosen_svr.score(),
                            );
                        }

                        inner.set_best_idx(svr_idx);
                    }

                    if let Some(barrier) = opt_barrier.take() {
                        barrier.wait().await;
                        debug!("ping {:?} server choosing task started", server_type);
                    }

                    time::delay_for(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC)).await;
                }
            });

            barrier.wait().await;
        }

        PingBalancer { inner }
    }

    pub fn servers(&self) -> Vec<Arc<ServerConfig>> {
        let mut vec = Vec::new();
        for svr in &self.inner.servers {
            vec.push(svr.config.clone());
        }
        vec
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
