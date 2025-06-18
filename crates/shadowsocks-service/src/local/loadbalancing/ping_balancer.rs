//! Load Balancer chooses server by statistic latency data collected from active probing

use std::{
    cmp,
    fmt::{self, Debug, Display},
    io,
    iter::Iterator,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use byte_string::ByteStr;
use futures::future;
use log::{debug, error, info, trace, warn};
use shadowsocks::{
    ServerConfig,
    config::{Mode, ServerSource},
    plugin::{Plugin, PluginMode},
    relay::{
        socks5::Address,
        tcprelay::proxy_stream::ProxyClientStream,
        udprelay::{MAXIMUM_UDP_PAYLOAD_SIZE, options::UdpSocketControlData, proxy_socket::ProxySocket},
    },
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::Notify,
    task::JoinHandle,
    time,
};

use crate::{config::ServerInstanceConfig, local::context::ServiceContext};

use super::{
    server_data::ServerIdent,
    server_stat::{DEFAULT_CHECK_INTERVAL_SEC, DEFAULT_CHECK_TIMEOUT_SEC, Score},
};

const EXPECTED_CHECK_POINTS_IN_CHECK_WINDOW: u32 = 67;

/// Remote Server Type
#[derive(Debug, Clone, Copy)]
pub enum ServerType {
    Tcp,
    Udp,
}

impl fmt::Display for ServerType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Tcp => f.write_str("TCP"),
            Self::Udp => f.write_str("UDP"),
        }
    }
}

/// Build a `PingBalancer`
pub struct PingBalancerBuilder {
    servers: Vec<Arc<ServerIdent>>,
    context: Arc<ServiceContext>,
    mode: Mode,
    max_server_rtt: Duration,
    check_interval: Duration,
    check_best_interval: Option<Duration>,
}

impl PingBalancerBuilder {
    pub fn new(context: Arc<ServiceContext>, mode: Mode) -> Self {
        Self {
            servers: Vec::new(),
            context,
            mode,
            max_server_rtt: Duration::from_secs(DEFAULT_CHECK_TIMEOUT_SEC),
            check_interval: Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC),
            check_best_interval: None,
        }
    }

    pub fn add_server(&mut self, server: ServerInstanceConfig) {
        let ident = ServerIdent::new(
            self.context.clone(),
            server,
            self.max_server_rtt,
            self.check_interval * EXPECTED_CHECK_POINTS_IN_CHECK_WINDOW,
        );
        self.servers.push(Arc::new(ident));
    }

    pub fn max_server_rtt(&mut self, rtt: Duration) {
        self.max_server_rtt = rtt;
    }

    pub fn check_interval(&mut self, intv: Duration) {
        self.check_interval = intv;
    }

    pub fn check_best_interval(&mut self, intv: Duration) {
        self.check_best_interval = Some(intv);
    }

    fn find_best_idx(servers: &[Arc<ServerIdent>], mode: Mode) -> (usize, usize) {
        if servers.is_empty() {
            trace!("init without any TCP and UDP servers");
            return (0, 0);
        }

        let mut best_tcp_idx = 0;
        let mut best_udp_idx = 0;

        if mode.enable_tcp() {
            let mut found_tcp_idx = false;
            for (idx, server) in servers.iter().enumerate() {
                if PingBalancerContext::check_server_tcp_enabled(server.server_config()) {
                    best_tcp_idx = idx;
                    found_tcp_idx = true;
                    break;
                }
            }

            if !found_tcp_idx {
                warn!(
                    "no valid TCP server serving for TCP clients, consider disable TCP with \"mode\": \"udp_only\", currently chose {}",
                    ServerConfigFormatter::new(servers[best_tcp_idx].server_config())
                );
            } else {
                trace!(
                    "init chose TCP server {}",
                    ServerConfigFormatter::new(servers[best_tcp_idx].server_config())
                );
            }
        }

        if mode.enable_udp() {
            let mut found_udp_idx = false;
            for (idx, server) in servers.iter().enumerate() {
                if PingBalancerContext::check_server_udp_enabled(server.server_config()) {
                    best_udp_idx = idx;
                    found_udp_idx = true;
                    break;
                }
            }

            if !found_udp_idx {
                warn!(
                    "no valid UDP server serving for UDP clients, consider disable UDP with \"mode\": \"tcp_only\", currently chose {}",
                    ServerConfigFormatter::new(servers[best_udp_idx].server_config())
                );
            } else {
                trace!(
                    "init chose UDP server {}",
                    ServerConfigFormatter::new(servers[best_udp_idx].server_config())
                );
            }
        }

        (best_tcp_idx, best_udp_idx)
    }

    pub async fn build(self) -> io::Result<PingBalancer> {
        if let Some(intv) = self.check_best_interval {
            if intv > self.check_interval {
                return Err(io::Error::other("check_interval must be >= check_best_interval"));
            }
        }

        let (shared_context, task_abortable) = PingBalancerContext::new(
            self.servers,
            self.context,
            self.mode,
            self.max_server_rtt,
            self.check_interval,
            self.check_best_interval,
        )
        .await?;

        Ok(PingBalancer {
            inner: Arc::new(PingBalancerInner {
                context: ArcSwap::new(shared_context),
                task_abortable: SpinMutex::new(task_abortable),
            }),
        })
    }
}

struct PingBalancerContextTask {
    checker_abortable: JoinHandle<()>,
    plugin_abortable: Option<JoinHandle<()>>,
}

impl Drop for PingBalancerContextTask {
    fn drop(&mut self) {
        self.checker_abortable.abort();
        if let Some(ref p) = self.plugin_abortable {
            p.abort();
        }
    }
}

struct PingBalancerContext {
    servers: Vec<Arc<ServerIdent>>,
    best_tcp_idx: AtomicUsize,
    best_udp_idx: AtomicUsize,
    context: Arc<ServiceContext>,
    mode: Mode,
    max_server_rtt: Duration,
    check_interval: Duration,
    check_best_interval: Option<Duration>,
    best_task_notify: Notify,
}

impl PingBalancerContext {
    fn best_tcp_server(&self) -> Arc<ServerIdent> {
        assert!(!self.is_empty(), "no available server");
        self.servers[self.best_tcp_idx.load(Ordering::Relaxed)].clone()
    }

    fn best_udp_server(&self) -> Arc<ServerIdent> {
        assert!(!self.is_empty(), "no available server");
        self.servers[self.best_udp_idx.load(Ordering::Relaxed)].clone()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

impl PingBalancerContext {
    pub(crate) async fn new(
        mut servers: Vec<Arc<ServerIdent>>,
        context: Arc<ServiceContext>,
        mode: Mode,
        max_server_rtt: Duration,
        check_interval: Duration,
        check_best_interval: Option<Duration>,
    ) -> io::Result<(Arc<Self>, PingBalancerContextTask)> {
        let plugin_abortable = {
            // Start plugins for TCP proxies

            let mut plugins = Vec::with_capacity(servers.len());

            for server in &mut servers {
                let server = Arc::get_mut(server).unwrap();
                let svr_cfg = server.server_config_mut();

                if let Some(p) = svr_cfg.plugin() {
                    // Start Plugin Process
                    let plugin = Plugin::start(p, svr_cfg.addr(), PluginMode::Client)?;
                    svr_cfg.set_plugin_addr(plugin.local_addr().into());
                    plugins.push(plugin);
                }
            }

            if plugins.is_empty() {
                None
            } else {
                // Load balancer will check all servers' score before server's actual start.
                // So we have to ensure all plugins have been started before that.

                let mut check_fut = Vec::with_capacity(plugins.len());

                for plugin in &plugins {
                    // 3 seconds is not a carefully selected value
                    // I choose that because any values bigger will make me felt too long.
                    check_fut.push(plugin.wait_started(Duration::from_secs(3)));
                }

                // Run all of them simultaneously
                let _ = future::join_all(check_fut).await;

                let plugin_abortable = tokio::spawn(async move {
                    let mut vfut = Vec::with_capacity(plugins.len());

                    for plugin in plugins {
                        vfut.push(async move {
                            match plugin.join().await {
                                Ok(status) => {
                                    error!("plugin exited with status: {}", status);
                                    Ok(())
                                }
                                Err(err) => {
                                    error!("plugin exited with error: {}", err);
                                    Err(err)
                                }
                            }
                        });
                    }

                    let _ = future::join_all(vfut).await;

                    panic!("all plugins are exited. all connections may fail, check your configuration");
                });

                Some(plugin_abortable)
            }
        };

        let (best_tcp_idx, best_udp_idx) = PingBalancerBuilder::find_best_idx(&servers, mode);

        let balancer_context = Self {
            servers,
            best_tcp_idx: AtomicUsize::new(best_tcp_idx),
            best_udp_idx: AtomicUsize::new(best_udp_idx),
            context,
            mode,
            max_server_rtt,
            check_interval,
            check_best_interval,
            best_task_notify: Notify::new(),
        };

        balancer_context.init_score().await;

        let shared_context = Arc::new(balancer_context);

        let checker_abortable = {
            let shared_context = shared_context.clone();
            tokio::spawn(async move { shared_context.checker_task().await })
        };

        Ok((
            shared_context,
            PingBalancerContextTask {
                checker_abortable,
                plugin_abortable,
            },
        ))
    }

    async fn init_score(&self) {
        if self.servers.is_empty() {
            return;
        }
        self.check_once(true).await;
    }

    fn check_server_tcp_enabled(svr_cfg: &ServerConfig) -> bool {
        svr_cfg.mode().enable_tcp() && svr_cfg.weight().tcp_weight() > 0.0
    }

    fn check_server_udp_enabled(svr_cfg: &ServerConfig) -> bool {
        svr_cfg.mode().enable_udp() && svr_cfg.weight().udp_weight() > 0.0
    }

    fn probing_required(&self) -> bool {
        if self.servers.is_empty() {
            return false;
        }

        let mut tcp_count = 0;
        let mut udp_count = 0;

        for server in self.servers.iter() {
            let svr_cfg = server.server_config();
            if self.mode.enable_tcp() && Self::check_server_tcp_enabled(svr_cfg) {
                tcp_count += 1;
            }
            if self.mode.enable_udp() && Self::check_server_udp_enabled(svr_cfg) {
                udp_count += 1;
            }
        }

        tcp_count > 1 || udp_count > 1
    }

    async fn checker_task(self: Arc<Self>) {
        if !self.probing_required() {
            self.checker_task_dummy().await
        } else {
            self.checker_task_real().await
        }
    }

    /// Dummy task that will do nothing if there only have one server in the balancer
    async fn checker_task_dummy(self: Arc<Self>) {
        future::pending().await
    }

    /// Check each servers' score and update the best server's index
    async fn check_once(&self, first_run: bool) {
        let servers = &self.servers;
        if servers.is_empty() {
            return;
        }

        let mut vfut_tcp = Vec::with_capacity(servers.len());
        let mut vfut_udp = Vec::with_capacity(servers.len());

        for server in servers.iter() {
            let svr_cfg = server.server_config();

            if self.mode.enable_tcp() && Self::check_server_tcp_enabled(svr_cfg) {
                let checker = PingChecker {
                    server: server.clone(),
                    server_type: ServerType::Tcp,
                    context: self.context.clone(),
                    max_server_rtt: self.max_server_rtt,
                };
                vfut_tcp.push(checker.check_update_score());
            }

            if self.mode.enable_udp() && Self::check_server_udp_enabled(svr_cfg) {
                let checker = PingChecker {
                    server: server.clone(),
                    server_type: ServerType::Udp,
                    context: self.context.clone(),
                    max_server_rtt: self.max_server_rtt,
                };
                vfut_udp.push(checker.check_update_score());
            }
        }

        let check_tcp = vfut_tcp.len() > 1;
        let check_udp = vfut_udp.len() > 1;

        if !check_tcp && !check_udp {
            return;
        }

        let vfut = if !check_tcp {
            vfut_udp
        } else if !check_udp {
            vfut_tcp
        } else {
            vfut_tcp.append(&mut vfut_udp);
            vfut_tcp
        };

        future::join_all(vfut).await;

        if self.mode.enable_tcp() && check_tcp {
            let old_best_idx = self.best_tcp_idx.load(Ordering::Acquire);

            let mut best_idx = 0;
            let mut best_score = u32::MAX;
            for (idx, server) in servers.iter().enumerate() {
                let score = server.tcp_score().score();
                if score < best_score {
                    best_idx = idx;
                    best_score = score;
                }
            }
            self.best_tcp_idx.store(best_idx, Ordering::Release);

            if first_run {
                info!(
                    "chose best TCP server {}",
                    ServerConfigFormatter::new(servers[best_idx].server_config())
                );
            } else if best_idx != old_best_idx {
                info!(
                    "switched best TCP server from {} to {}",
                    ServerConfigFormatter::new(servers[old_best_idx].server_config()),
                    ServerConfigFormatter::new(servers[best_idx].server_config())
                );
            } else {
                debug!(
                    "kept best TCP server {}",
                    ServerConfigFormatter::new(servers[old_best_idx].server_config())
                );
            }
        }

        if self.mode.enable_udp() && check_udp {
            let old_best_idx = self.best_udp_idx.load(Ordering::Acquire);

            let mut best_idx = 0;
            let mut best_score = u32::MAX;
            for (idx, server) in servers.iter().enumerate() {
                let score = server.udp_score().score();
                if score < best_score {
                    best_idx = idx;
                    best_score = score;
                }
            }
            self.best_udp_idx.store(best_idx, Ordering::Release);

            if first_run {
                info!(
                    "chose best UDP server {}",
                    ServerConfigFormatter::new(servers[best_idx].server_config())
                );
            } else if best_idx != old_best_idx {
                info!(
                    "switched best UDP server from {} to {}",
                    ServerConfigFormatter::new(servers[old_best_idx].server_config()),
                    ServerConfigFormatter::new(servers[best_idx].server_config())
                );
            } else {
                debug!(
                    "kept best UDP server {}",
                    ServerConfigFormatter::new(servers[old_best_idx].server_config())
                );
            }
        }
    }

    /// Check the best server only
    async fn check_best_server(&self) {
        let servers = &self.servers;
        if servers.is_empty() {
            return;
        }

        let mut vfut = Vec::new();

        let best_tcp_idx = self.best_tcp_idx.load(Ordering::Acquire);
        let best_udp_idx = self.best_udp_idx.load(Ordering::Acquire);

        let best_tcp_server = &servers[best_tcp_idx];
        let best_tcp_svr_cfg = best_tcp_server.server_config();
        let best_udp_server = &servers[best_udp_idx];
        let best_udp_svr_cfg = best_udp_server.server_config();

        let mut check_tcp = false;
        let mut check_udp = false;

        if self.mode.enable_tcp() && Self::check_server_tcp_enabled(best_tcp_svr_cfg) {
            let checker = PingChecker {
                server: best_tcp_server.clone(),
                server_type: ServerType::Tcp,
                context: self.context.clone(),
                max_server_rtt: self.max_server_rtt,
            };
            vfut.push(checker.check_update_score());
            check_tcp = true;
        }

        if self.mode.enable_udp() && Self::check_server_udp_enabled(best_udp_svr_cfg) {
            let checker = PingChecker {
                server: best_udp_server.clone(),
                server_type: ServerType::Udp,
                context: self.context.clone(),
                max_server_rtt: self.max_server_rtt,
            };
            vfut.push(checker.check_update_score());
            check_udp = true;
        }

        future::join_all(vfut).await;

        if self.mode.enable_tcp() && check_tcp {
            let old_best_idx = self.best_tcp_idx.load(Ordering::Acquire);

            let mut best_idx = 0;
            let mut best_score = u32::MAX;
            for (idx, server) in servers.iter().enumerate() {
                let score = server.tcp_score().score();
                if score < best_score {
                    best_idx = idx;
                    best_score = score;
                }
            }
            self.best_tcp_idx.store(best_idx, Ordering::Release);

            if best_idx != old_best_idx {
                if best_idx != old_best_idx {
                    info!(
                        "switched best TCP server from {} to {} (best check)",
                        ServerConfigFormatter::new(servers[old_best_idx].server_config()),
                        ServerConfigFormatter::new(servers[best_idx].server_config())
                    );
                } else {
                    debug!(
                        "kept best TCP server {} (best check)",
                        ServerConfigFormatter::new(servers[old_best_idx].server_config())
                    );
                }
            }
        }

        if self.mode.enable_udp() && check_udp {
            let old_best_idx = self.best_udp_idx.load(Ordering::Acquire);

            let mut best_idx = 0;
            let mut best_score = u32::MAX;
            for (idx, server) in servers.iter().enumerate() {
                let score = server.udp_score().score();
                if score < best_score {
                    best_idx = idx;
                    best_score = score;
                }
            }
            self.best_udp_idx.store(best_idx, Ordering::Release);

            if best_idx != old_best_idx {
                if best_idx != old_best_idx {
                    info!(
                        "switched best UDP server from {} to {} (best check)",
                        ServerConfigFormatter::new(servers[old_best_idx].server_config()),
                        ServerConfigFormatter::new(servers[best_idx].server_config())
                    );
                } else {
                    debug!(
                        "kept best UDP server {} (best check)",
                        ServerConfigFormatter::new(servers[old_best_idx].server_config())
                    );
                }
            }
        }
    }

    async fn checker_task_real(&self) {
        if self.check_best_interval.is_none() {
            return self.checker_task_all_servers().await;
        }

        let best = self.checker_task_best_server();
        let all = self.checker_task_all_servers();
        futures::join!(best, all);
    }

    async fn checker_task_all_servers(&self) {
        if let Some(check_best_interval) = self.check_best_interval {
            // Get at least 10 points to get the precise scores

            let interval = cmp::min(check_best_interval, self.check_interval);

            let mut count = 0;
            while count < EXPECTED_CHECK_POINTS_IN_CHECK_WINDOW {
                time::sleep(interval).await;

                // Sleep before check.
                // PingBalancer already checked once when constructing
                self.check_once(false).await;

                count += 1;
            }

            self.best_task_notify.notify_one();

            trace!("finished initializing server scores");
        }

        loop {
            time::sleep(self.check_interval).await;

            // Sleep before check.
            // PingBalancer already checked once when constructing
            self.check_once(false).await;
        }
    }

    async fn checker_task_best_server(&self) {
        // Wait until checker_task_all_servers notify.
        // Because when server starts, the scores are unstable, so we have to run check_all for multiple times
        self.best_task_notify.notified().await;

        let check_best_interval = self.check_best_interval.unwrap();

        loop {
            time::sleep(check_best_interval).await;

            // Sleep before check.
            // PingBalancer already checked once when constructing
            self.check_best_server().await;
        }
    }
}

struct PingBalancerInner {
    context: ArcSwap<PingBalancerContext>,
    task_abortable: SpinMutex<PingBalancerContextTask>,
}

impl Drop for PingBalancerInner {
    fn drop(&mut self) {
        trace!("ping balancer stopped");
    }
}

/// Balancer with active probing
#[derive(Clone)]
pub struct PingBalancer {
    inner: Arc<PingBalancerInner>,
}

impl PingBalancer {
    /// Get service context
    pub fn context(&self) -> Arc<ServiceContext> {
        let context = self.inner.context.load();
        context.context.clone()
    }

    /// Pick the best TCP server
    pub fn best_tcp_server(&self) -> Arc<ServerIdent> {
        let context = self.inner.context.load();
        context.best_tcp_server()
    }

    /// Pick the best UDP server
    pub fn best_udp_server(&self) -> Arc<ServerIdent> {
        let context = self.inner.context.load();
        context.best_udp_server()
    }

    /// Check if there is no available server
    #[inline]
    pub fn is_empty(&self) -> bool {
        let context = self.inner.context.load();
        context.is_empty()
    }

    /// Get the server list
    pub fn servers(&self) -> PingServerIter<'_> {
        let context = self.inner.context.load();
        let servers: &Vec<Arc<ServerIdent>> = unsafe { &*(&context.servers as *const _) };
        PingServerIter {
            context: context.clone(),
            iter: servers.iter(),
        }
    }

    /// Reset servers in load balancer. Designed for auto-reloading configuration file.
    pub async fn reset_servers(
        &self,
        servers: Vec<ServerInstanceConfig>,
        replace_server_sources: &[ServerSource],
    ) -> io::Result<()> {
        let old_context = self.inner.context.load();

        let mut old_servers = old_context.servers.clone();
        let mut idx = 0;
        while idx < old_servers.len() {
            let source_match = replace_server_sources
                .iter()
                .any(|src| *src == old_servers[idx].server_config().source());
            if source_match {
                old_servers.swap_remove(idx);
            } else {
                idx += 1;
            }
        }

        trace!(
            "ping balancer going to replace {} servers (total: {}) with {} servers, sources: {:?}",
            old_context.servers.len() - old_servers.len(),
            old_context.servers.len(),
            servers.len(),
            replace_server_sources
        );

        let mut servers = servers
            .into_iter()
            .map(|s| {
                Arc::new(ServerIdent::new(
                    old_context.context.clone(),
                    s,
                    old_context.max_server_rtt,
                    old_context.check_interval * EXPECTED_CHECK_POINTS_IN_CHECK_WINDOW,
                ))
            })
            .collect::<Vec<Arc<ServerIdent>>>();

        // Recreate a new instance for old servers (old server instance may still being held by clients)
        for old_server in old_servers {
            servers.push(Arc::new(ServerIdent::new(
                old_context.context.clone(),
                old_server.server_instance_config().clone(),
                old_context.max_server_rtt,
                old_context.check_interval * EXPECTED_CHECK_POINTS_IN_CHECK_WINDOW,
            )));
        }

        trace!("ping balancer merged {} new servers", servers.len());

        let (shared_context, task_abortable) = PingBalancerContext::new(
            servers,
            old_context.context.clone(),
            old_context.mode,
            old_context.max_server_rtt,
            old_context.check_interval,
            old_context.check_best_interval,
        )
        .await?;

        {
            // Stop the previous task and replace with the new task
            let mut abortable = self.inner.task_abortable.lock();
            *abortable = task_abortable;
        }

        // Replace with the new context
        self.inner.context.store(shared_context);

        Ok(())
    }
}

impl Debug for PingBalancer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context = self.inner.context.load();

        f.debug_struct("PingBalancer")
            .field("servers", &context.servers)
            .field("best_tcp_idx", &context.best_tcp_idx.load(Ordering::Relaxed))
            .field("best_udp_idx", &context.best_udp_idx.load(Ordering::Relaxed))
            .finish()
    }
}

struct PingChecker {
    server: Arc<ServerIdent>,
    server_type: ServerType,
    context: Arc<ServiceContext>,
    max_server_rtt: Duration,
}

impl PingChecker {
    /// Checks server's score and update into `ServerScore<E>`
    async fn check_update_score(self) {
        let server_score = match self.server_type {
            ServerType::Tcp => self.server.tcp_score(),
            ServerType::Udp => self.server.udp_score(),
        };

        let (score, stat_data) = match self.check_delay().await {
            Ok(d) => server_score.push_score_fetch_statistic(Score::Latency(d)).await,
            // Penalty
            Err(..) => server_score.push_score_fetch_statistic(Score::Errored).await,
        };

        if stat_data.fail_rate > 0.8 {
            warn!(
                "balancer: checked & updated remote {} server {} (score: {}), {:?}",
                self.server_type,
                ServerConfigFormatter::new(self.server.server_config()),
                score,
                stat_data,
            );
        } else {
            debug!(
                "balancer: checked & updated remote {} server {} (score: {}), {:?}",
                self.server_type,
                ServerConfigFormatter::new(self.server.server_config()),
                score,
                stat_data,
            );
        }
    }

    /// Detect TCP connectivity with Chromium [Network Portal Detection](https://www.chromium.org/chromium-os/chromiumos-design-docs/network-portal-detection)
    #[allow(dead_code)]
    async fn check_request_tcp_chromium(&self) -> io::Result<()> {
        use std::io::{Error, ErrorKind};

        const GET_BODY: &[u8] =
            b"GET /generate_204 HTTP/1.1\r\nHost: clients3.google.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("clients3.google.com".to_owned(), 80);

        let mut stream = ProxyClientStream::connect_with_opts(
            self.context.context(),
            self.server.server_config(),
            &addr,
            self.server.connect_opts_ref(),
        )
        .await?;
        stream.write_all(GET_BODY).await?;

        let mut reader = BufReader::new(stream);

        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await?;

        let mut headers = [httparse::EMPTY_HEADER; 1];
        let mut response = httparse::Response::new(&mut headers);

        if response.parse(&buf).is_ok() && matches!(response.code, Some(204)) {
            return Ok(());
        }

        Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "unexpected response from http://clients3.google.com/generate_204, {:?}",
                ByteStr::new(&buf)
            ),
        ))
    }

    /// Detect TCP connectivity with Firefox's http://detectportal.firefox.com/success.txt
    async fn check_request_tcp_firefox(&self) -> io::Result<()> {
        use std::io::{Error, ErrorKind};

        const GET_BODY: &[u8] =
            b"GET /success.txt HTTP/1.1\r\nHost: detectportal.firefox.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("detectportal.firefox.com".to_owned(), 80);

        let mut stream = ProxyClientStream::connect_with_opts(
            self.context.context(),
            self.server.server_config(),
            &addr,
            self.server.connect_opts_ref(),
        )
        .await?;
        stream.write_all(GET_BODY).await?;

        let mut reader = BufReader::new(stream);

        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await?;

        let mut headers = [httparse::EMPTY_HEADER; 1];
        let mut response = httparse::Response::new(&mut headers);

        if response.parse(&buf).is_ok() && matches!(response.code, Some(200) | Some(204)) {
            return Ok(());
        }

        Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "unexpected response from http://detectportal.firefox.com/success.txt, {:?}",
                ByteStr::new(&buf)
            ),
        ))
    }

    async fn check_request_udp(&self) -> io::Result<()> {
        // TransactionID: 0x1234
        // Flags: 0x0100 RD
        // Questions: 0x0001
        // Answer RRs: 0x0000
        // Authority RRs: 0x0000
        // Additional RRs: 0x0000
        // Queries
        //    - QNAME: \x07 firefox \x03 com \x00
        //    - QTYPE: 0x0001 A
        //    - QCLASS: 0x0001 IN
        const DNS_QUERY: &[u8] =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07firefox\x03com\x00\x00\x01\x00\x01";

        let addr = Address::SocketAddress(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53));

        let client = ProxySocket::connect_with_opts(
            self.context.context(),
            self.server.server_config(),
            self.server.connect_opts_ref(),
        )
        .await?;

        let mut control = UdpSocketControlData::default();
        control.client_session_id = rand::random::<u64>();
        control.packet_id = 1;
        client.send_with_ctrl(&addr, &control, DNS_QUERY).await?;

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (n, ..) = client.recv(&mut buffer).await?;

        let dns_answer = &buffer[..n];

        // DNS packet must have at least 6 * 2 bytes
        if dns_answer.len() < 12 || &dns_answer[0..2] != b"\x12\x34" {
            use std::io::{Error, ErrorKind};

            debug!("unexpected response from 8.8.8.8:53, {:?}", ByteStr::new(dns_answer));

            let err = Error::new(ErrorKind::InvalidData, "unexpected response from 8.8.8.8:53");
            return Err(err);
        }

        Ok(())
    }

    async fn check_request(&self) -> io::Result<()> {
        match self.server_type {
            ServerType::Tcp => self.check_request_tcp_firefox().await,
            ServerType::Udp => self.check_request_udp().await,
        }
    }

    async fn check_delay(&self) -> io::Result<u32> {
        let start = Instant::now();

        // Send HTTP GET and read the first byte
        let res = time::timeout(self.max_server_rtt, self.check_request()).await;

        let elapsed = Instant::now() - start;
        let elapsed = elapsed.as_secs() as u32 * 1000 + elapsed.subsec_millis(); // Converted to ms
        match res {
            Ok(Ok(..)) => {
                // Got the result ... record its time
                trace!(
                    "checked remote {} server {} latency with {} ms",
                    self.server_type,
                    ServerConfigFormatter::new(self.server.server_config()),
                    elapsed
                );
                Ok(elapsed)
            }
            Ok(Err(err)) => {
                debug!(
                    "failed to check {} server {}, error: {}",
                    self.server_type,
                    ServerConfigFormatter::new(self.server.server_config()),
                    err
                );

                // NOTE: connection / handshake error, server is down
                Err(err)
            }
            Err(..) => {
                use std::io::ErrorKind;

                // Timeout
                trace!(
                    "checked remote {} server {} latency timeout, elapsed {} ms",
                    self.server_type,
                    ServerConfigFormatter::new(self.server.server_config()),
                    elapsed
                );

                // NOTE: timeout exceeded. Count as error.
                Err(ErrorKind::TimedOut.into())
            }
        }
    }
}

struct ServerConfigFormatter<'a> {
    server_config: &'a ServerConfig,
}

impl<'a> ServerConfigFormatter<'a> {
    fn new(server_config: &'a ServerConfig) -> Self {
        ServerConfigFormatter { server_config }
    }
}

impl Display for ServerConfigFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.server_config.remarks() {
            None => Display::fmt(self.server_config.addr(), f),
            Some(remarks) => {
                if remarks.is_empty() {
                    Display::fmt(self.server_config.addr(), f)
                } else {
                    write!(f, "{} ({})", self.server_config.addr(), remarks)
                }
            }
        }
    }
}

/// Server Iterator
pub struct PingServerIter<'a> {
    #[allow(dead_code)]
    context: Arc<PingBalancerContext>,
    iter: std::slice::Iter<'a, Arc<ServerIdent>>,
}

impl<'a> Iterator for PingServerIter<'a> {
    type Item = &'a ServerIdent;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(AsRef::as_ref)
    }
}
