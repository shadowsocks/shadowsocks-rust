//! Shadowsocks Server instance

use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use log::{error, trace};
use shadowsocks::{
    config::{ManagerAddr, ServerConfig, ServerType},
    context::{Context, SharedContext},
    dns_resolver::DnsResolver,
    net::ConnectOpts,
    plugin::{Plugin, PluginMode},
    ManagerClient,
};
use tokio::time;

use crate::{
    config::{ClientConfig, Mode},
    local::acl::AccessControl,
    net::FlowStat,
};

use super::{tcprelay::TcpServer, udprelay::UdpServer};

pub struct Server {
    context: SharedContext,
    svr_cfg: ServerConfig,
    client_config: Option<ClientConfig>,
    mode: Mode,
    flow_stat: Arc<FlowStat>,
    connect_opts: ConnectOpts,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    manager_addr: Option<ManagerAddr>,
    nodelay: bool,
    acl: Option<Arc<AccessControl>>,
}

impl Server {
    pub fn new(svr_cfg: ServerConfig) -> Server {
        Server::with_context(Context::new_shared(ServerType::Server), svr_cfg)
    }

    pub(crate) fn with_context(context: SharedContext, svr_cfg: ServerConfig) -> Server {
        Server {
            context,
            svr_cfg,
            client_config: None,
            mode: Mode::TcpOnly,
            flow_stat: Arc::new(FlowStat::new()),
            connect_opts: ConnectOpts::default(),
            udp_expiry_duration: None,
            udp_capacity: 512,
            manager_addr: None,
            nodelay: false,
            acl: None,
        }
    }

    pub fn flow_stat(&self) -> &Arc<FlowStat> {
        &self.flow_stat
    }

    pub fn set_client_config(&mut self, client_config: ClientConfig) {
        self.client_config = Some(client_config);
    }

    pub fn set_connect_opts(&mut self, opts: ConnectOpts) {
        self.connect_opts = opts;
    }

    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = c;
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn set_manager_addr(&mut self, manager_addr: ManagerAddr) {
        self.manager_addr = Some(manager_addr);
    }

    pub fn config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        self.acl = Some(acl);
    }

    pub async fn run(mut self) -> io::Result<()> {
        let mut vfut = Vec::new();

        if self.mode.enable_tcp() {
            if let Some(plugin_cfg) = self.svr_cfg.plugin() {
                let plugin = Plugin::start(plugin_cfg, self.svr_cfg.addr(), PluginMode::Server)?;
                self.svr_cfg.set_plugin_addr(plugin.local_addr().into());
                vfut.push(async move { plugin.join().map(|r| r.map(|_| ())).await }.boxed());
            }

            let tcp_fut = self.run_tcp_server().boxed();
            vfut.push(tcp_fut);
        }

        if self.mode.enable_udp() {
            let udp_fut = self.run_udp_server().boxed();
            vfut.push(udp_fut);
        }

        if self.manager_addr.is_some() {
            let manager_fut = self.run_manager_report().boxed();
            vfut.push(manager_fut);
        }

        let _ = future::select_all(vfut).await;

        let err = io::Error::new(ErrorKind::Other, "server exited unexpectly");
        Err(err)
    }

    async fn run_tcp_server(&self) -> io::Result<()> {
        let server = TcpServer::new(
            self.context.clone(),
            self.flow_stat.clone(),
            self.connect_opts.clone(),
            self.nodelay,
            self.acl.clone(),
        );
        server.run(&self.svr_cfg).await
    }

    async fn run_udp_server(&self) -> io::Result<()> {
        let udp_expiry_duration = self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60));

        let server = UdpServer::new(
            self.context.clone(),
            self.flow_stat.clone(),
            self.connect_opts.clone(),
            udp_expiry_duration,
            self.udp_capacity,
            self.acl.clone(),
        );
        server.run(&self.svr_cfg).await
    }

    async fn run_manager_report(&self) -> io::Result<()> {
        let manager_addr = self.manager_addr.as_ref().unwrap();

        loop {
            match ManagerClient::connect(&self.context, manager_addr).await {
                Err(err) => {
                    error!("failed to connect manager {}, error: {}", manager_addr, err);
                }
                Ok(mut client) => {
                    use shadowsocks::manager::protocol::StatRequest;

                    let mut stat = HashMap::new();
                    stat.insert(self.svr_cfg.addr().port(), self.flow_stat.tx() + self.flow_stat.rx());

                    let req = StatRequest { stat };

                    if let Err(err) = client.stat(&req).await {
                        error!(
                            "failed to send stat to manager {}, error: {}, {:?}",
                            manager_addr, err, req
                        );
                    } else {
                        trace!("report to manager {}, {:?}", manager_addr, req);
                    }
                }
            }

            // Report every 10 seconds
            time::sleep(Duration::from_secs(10)).await;
        }
    }
}
