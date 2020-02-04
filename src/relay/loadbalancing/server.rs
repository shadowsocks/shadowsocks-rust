use std::{
    collections::VecDeque,
    fmt,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{
    config::{Config, ServerConfig},
    context::{Context, SharedContext},
    relay::{
        socks5::Address,
        tcprelay::client::ServerClient as TcpServerClient,
        udprelay::client::ServerClient as UdpServerClient,
    },
};

use log::{debug, info};
use tokio::{
    self,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Barrier, Mutex},
    time,
};

const MAX_LATENCY_QUEUE_SIZE: usize = 37;
const DEFAULT_CHECK_INTERVAL_SEC: u64 = 6;
const DEFAULT_CHECK_TIMEOUT_SEC: u64 = 2; // Latency shouldn't greater than 2 secs, that's too long

/// Identifier of a valid server
pub trait ServerData: Send + Sync {
    fn create_server(context: &SharedContext, server_idx: usize, data: &SharedServerStatisticData) -> Self;
}

struct ServerStatisticData {
    /// Median of latency time
    ///
    /// Use median instead of average time,
    /// because probing result may have some really bad cases
    rtt: u64,
    /// Total_Fail / Total_Probe
    fail_rate: f64,
    /// Recently probe data
    latency_queue: VecDeque<Score>,
}

impl ServerStatisticData {
    fn new() -> ServerStatisticData {
        ServerStatisticData {
            rtt: u64::max_value(),
            fail_rate: 100.0,
            latency_queue: VecDeque::new(),
        }
    }

    fn score(&self) -> u64 {
        // Normalize rtt
        let nrtt = self.rtt as f64 / DEFAULT_CHECK_TIMEOUT_SEC as f64;

        // Score = norm_lat + prop_err
        //
        // 1. The lower latency, the better
        // 2. The lower errored count, the better
        ((nrtt + self.fail_rate) * 1000.0) as u64
    }

    fn push_score(&mut self, score: Score) -> u64 {
        self.latency_queue.push_back(score);

        // Only records recently MAX_LATENCY_QUEUE_SIZE probe data
        if self.latency_queue.len() > MAX_LATENCY_QUEUE_SIZE {
            self.latency_queue.pop_front();
        }

        self.recalculate_score()
    }

    fn recalculate_score(&mut self) -> u64 {
        let mut vlat = Vec::with_capacity(self.latency_queue.len());
        let mut cerr = 0;
        for s in &self.latency_queue {
            match *s {
                Score::Errored => cerr += 1,
                Score::Latency(lat) => vlat.push(lat),
            }
        }

        if !vlat.is_empty() {
            vlat.sort();

            // Find median of latency
            let mid = vlat.len() / 2;

            self.rtt = if vlat.len() % 2 == 0 {
                (vlat[mid] + vlat[mid - 1]) / 2
            } else {
                vlat[mid]
            };
        }

        // Error rate
        self.fail_rate = cerr as f64 / self.latency_queue.len() as f64;

        self.score()
    }

    pub fn report_failure(&mut self) -> u64 {
        self.push_score(Score::Errored)
    }
}

/// Shared handle for mutating server's statistic data
#[derive(Clone)]
pub struct SharedServerStatisticData(Arc<Mutex<ServerStatisticData>>);

impl SharedServerStatisticData {
    fn new() -> SharedServerStatisticData {
        SharedServerStatisticData(Arc::new(Mutex::new(ServerStatisticData::new())))
    }

    pub async fn report_failure(&self) -> u64 {
        let mut data = self.0.lock().await;
        data.report_failure()
    }

    async fn push_score(&self, score: Score) -> u64 {
        let mut data = self.0.lock().await;
        data.push_score(score)
    }

    pub async fn score(&self) -> u64 {
        let data = self.0.lock().await;
        data.score()
    }
}

/// Server Statistic scores
pub struct ServerStatistic<S: ServerData> {
    server: S,
    context: SharedContext,
    server_idx: usize,
    data: SharedServerStatisticData,
}

pub type SharedServerStatistic<S> = Arc<ServerStatistic<S>>;

impl<S: ServerData> ServerStatistic<S> {
    fn new(context: SharedContext, server_idx: usize) -> ServerStatistic<S> {
        let data = SharedServerStatisticData::new();

        ServerStatistic {
            server: S::create_server(&context, server_idx, &data),
            context,
            server_idx,
            data,
        }
    }

    fn new_shared(context: SharedContext, server_idx: usize) -> SharedServerStatistic<S> {
        Arc::new(ServerStatistic::new(context, server_idx))
    }

    pub fn server_config(&self) -> &ServerConfig {
        self.context.server_config(self.server_idx)
    }

    pub fn server(&self) -> &S {
        &self.server
    }

    pub fn context(&self) -> &Context {
        &*self.context
    }

    pub fn config(&self) -> &Config {
        self.context.config()
    }

    async fn push_score(&self, score: Score) -> u64 {
        self.data.push_score(score).await
    }

    pub async fn score(&self) -> u64 {
        self.data.score().await
    }

    pub async fn report_failure(&self) -> u64 {
        self.data.report_failure().await
    }
}

#[derive(Debug, Copy, Clone)]
enum Score {
    Latency(u64),
    Errored,
}

#[derive(Debug, Clone, Copy)]
pub enum ServerType {
    Tcp,
    Udp,
}

impl fmt::Display for ServerType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ServerType::Tcp => f.write_str("TCP"),
            ServerType::Udp => f.write_str("UDP"),
        }
    }
}

struct BestServer<S: ServerData> {
    servers: Vec<SharedServerStatistic<S>>,
    best_idx: AtomicUsize,
}

type SharedBestServer<S> = Arc<BestServer<S>>;

impl<S: ServerData> BestServer<S> {
    fn new(servers: Vec<SharedServerStatistic<S>>) -> BestServer<S> {
        BestServer {
            servers,
            best_idx: AtomicUsize::new(0),
        }
    }

    fn new_shared(servers: Vec<SharedServerStatistic<S>>) -> SharedBestServer<S> {
        Arc::new(BestServer::new(servers))
    }

    fn pick_server(&self) -> SharedServerStatistic<S> {
        let idx = self.best_idx.load(Ordering::Relaxed);
        self.servers[idx].clone()
    }

    async fn recalculate_best_server(&self) -> Option<(usize, usize)> {
        let current_best_idx = self.best_idx.load(Ordering::Relaxed);

        let mut best_idx = 0;
        let mut best_score = u64::max_value();

        for (idx, svr) in self.servers.iter().enumerate() {
            let score = svr.score().await;
            if score < best_score {
                best_idx = idx;
                best_score = score;
            }
        }

        if best_idx != current_best_idx {
            self.best_idx.store(best_idx, Ordering::Relaxed);

            Some((current_best_idx, best_idx))
        } else {
            None
        }
    }
}

/// Load balancer based on pinging latencies of all servers
#[derive(Clone)]
pub struct PingBalancer<S: ServerData> {
    best: SharedBestServer<S>,
}

impl<S: ServerData + 'static> PingBalancer<S> {
    /// Create a PingBalancer
    pub async fn new(context: SharedContext, server_type: ServerType) -> PingBalancer<S> {
        let server_count = context.config().server.len();
        let mut servers = Vec::with_capacity(server_count);

        // Check only required if servers count > 1, otherwise, always use the first one
        let check_required = server_count > 1;
        // Barrier count = current + probing tasks
        let check_barrier = Arc::new(Barrier::new(1 + server_count));

        for idx in 0..server_count {
            let stat = ServerStatistic::<S>::new_shared(context.clone(), idx);

            if check_required {
                let stat = stat.clone();
                let context = context.clone();
                let check_barrier = check_barrier.clone();

                // Start a background task for probing
                tokio::spawn(async move {
                    // Check once for initializing data
                    PingBalancer::<S>::check_update_score(&stat, server_type).await;
                    check_barrier.wait().await;

                    while context.server_running() {
                        PingBalancer::<S>::check_update_score(&stat, server_type).await;
                        time::delay_for(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC)).await;
                    }

                    debug!(
                        "Probing task for remote {} server {} exited",
                        server_type,
                        stat.server_config().addr()
                    );
                });
            }

            servers.push(stat);
        }

        let best = BestServer::new_shared(servers);

        if check_required {
            // Wait all tasks start (run at least one round)
            check_barrier.wait().await;

            // Reinitialize a Barrier for waiting choosing task
            let check_barrier = Arc::new(Barrier::new(2));
            let best = best.clone();

            {
                let context = context.clone();
                let check_barrier = check_barrier.clone();

                tokio::spawn(async move {
                    // Check once for initializing data
                    best.recalculate_best_server().await;
                    check_barrier.wait().await;

                    while context.server_running() {
                        if let Some((old_idx, new_idx)) = best.recalculate_best_server().await {
                            info!(
                                "Switched {} server from {} to {}",
                                server_type,
                                context.server_config(old_idx).addr(),
                                context.server_config(new_idx).addr()
                            );
                        }

                        time::delay_for(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC)).await;
                    }
                });
            }

            // Wait for choosing task to check at least once
            check_barrier.wait().await;
        }

        PingBalancer { best }
    }

    async fn check_update_score(stat: &ServerStatistic<S>, server_type: ServerType) {
        let score = match PingBalancer::<S>::check_delay(stat, server_type).await {
            Ok(d) => stat.push_score(Score::Latency(d)).await,
            Err(..) => stat.push_score(Score::Errored).await, // Penalty
        };

        debug!(
            "Updated remote {} server {} (score: {})",
            server_type,
            stat.server_config().addr(),
            score
        );
    }

    async fn check_request_tcp(stat: &ServerStatistic<S>) -> io::Result<()> {
        static GET_BODY: &[u8] =
            b"GET /generate_204 HTTP/1.1\r\nHost: dl.google.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("dl.google.com".to_owned(), 80);

        let TcpServerClient { mut stream } =
            TcpServerClient::connect(stat.context(), &addr, stat.server_config()).await?;
        stream.write_all(GET_BODY).await?;
        stream.flush().await?;
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;

        Ok(())
    }

    async fn check_request_udp(stat: &ServerStatistic<S>) -> io::Result<()> {
        static DNS_QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";

        let addr = Address::SocketAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));

        let mut client = UdpServerClient::new(stat.server_config()).await?;
        client.send_to(stat.context(), &addr, DNS_QUERY).await?;
        let _ = client.recv_from(stat.context()).await?;

        Ok(())
    }

    async fn check_request(stat: &ServerStatistic<S>, server_type: ServerType) -> io::Result<()> {
        match server_type {
            ServerType::Tcp => PingBalancer::<S>::check_request_tcp(stat).await,
            ServerType::Udp => PingBalancer::<S>::check_request_udp(stat).await,
        }
    }

    async fn check_delay(stat: &ServerStatistic<S>, server_type: ServerType) -> io::Result<u64> {
        let start = Instant::now();

        // Send HTTP GET and read the first byte
        let timeout = Duration::from_secs(DEFAULT_CHECK_TIMEOUT_SEC);
        let res = time::timeout(timeout, PingBalancer::<S>::check_request(stat, server_type)).await;

        let elapsed = Instant::now() - start;
        let elapsed = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis()); // Converted to ms
        match res {
            Ok(Ok(..)) => {
                // Got the result ... record its time
                debug!(
                    "Checked remote {} server {} latency with {} ms",
                    server_type,
                    stat.server_config().addr(),
                    elapsed
                );
                Ok(elapsed)
            }
            Ok(Err(err)) => {
                debug!(
                    "Failed to check {} server {}, error: {}",
                    server_type,
                    stat.server_config().addr(),
                    err
                );

                // NOTE: connection / handshake error, server is down
                Err(err)
            }
            Err(..) => {
                // Timeout
                debug!(
                    "Checked remote {} server {} latency timeout, elapsed {} ms",
                    server_type,
                    stat.server_config().addr(),
                    elapsed
                );

                // NOTE: timeout is still available, but server is too slow
                Ok(elapsed)
            }
        }
    }
}

impl<S: ServerData> PingBalancer<S> {
    /// Pick the best server with current known statistic data
    ///
    /// Return a `Arc` shared server statistic reference
    pub fn pick_server(&self) -> SharedServerStatistic<S> {
        self.best.pick_server()
    }
}

/// A default struct for default ping balancer
pub struct EmptyServerData;

impl ServerData for EmptyServerData {
    fn create_server(_: &SharedContext, _: usize, _: &SharedServerStatisticData) -> EmptyServerData {
        EmptyServerData
    }
}

/// A PingBalancer without customized ServerData
pub type PlainPingBalancer = PingBalancer<EmptyServerData>;

/// Shared PlainServerStatistic
pub type SharedPlainServerStatistic = SharedServerStatistic<EmptyServerData>;
