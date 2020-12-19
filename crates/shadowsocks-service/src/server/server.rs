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
    config::{ManagerAddr, ServerConfig},
    dns_resolver::DnsResolver,
    net::ConnectOpts,
    plugin::{Plugin, PluginMode},
    ManagerClient,
};
use tokio::time;

use crate::{acl::AccessControl, config::Mode, net::FlowStat};

use super::{context::ServiceContext, tcprelay::TcpServer, udprelay::UdpServer};

/// Shadowsocks Server
pub struct Server {
    context: Arc<ServiceContext>,
    svr_cfg: ServerConfig,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    manager_addr: Option<ManagerAddr>,
    nodelay: bool,
}

impl Server {
    /// Create a new server from configuration
    pub fn new(svr_cfg: ServerConfig) -> Server {
        Server::with_context(Arc::new(ServiceContext::new()), svr_cfg)
    }

    /// Create a new server with context
    pub fn with_context(context: Arc<ServiceContext>, svr_cfg: ServerConfig) -> Server {
        Server {
            context,
            svr_cfg,
            mode: Mode::TcpOnly,
            udp_expiry_duration: None,
            udp_capacity: 512,
            manager_addr: None,
            nodelay: false,
        }
    }

    /// Get flow statistic
    pub fn flow_stat(&self) -> Arc<FlowStat> {
        self.context.flow_stat()
    }

    /// Get flow statistic reference
    pub fn flow_stat_ref(&self) -> &FlowStat {
        self.context.flow_stat_ref()
    }

    /// Set `ConnectOpts`
    pub fn set_connect_opts(&mut self, opts: ConnectOpts) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ConnectOpts on a shared context");
        context.set_connect_opts(opts)
    }

    /// Set UDP association's expiry duration
    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    /// Set total UDP associations to be kept in one server
    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = c;
    }

    /// Set server's mode
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Set manager's address to report `stat`
    pub fn set_manager_addr(&mut self, manager_addr: ManagerAddr) {
        self.manager_addr = Some(manager_addr);
    }

    /// Get server's configuration
    pub fn config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    /// Set `TCP_NODELAY`
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    /// Set customized DNS resolver
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    /// Set access control list
    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set ACL on a shared context");
        context.set_acl(acl);
    }

    /// Start serving
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
        let server = TcpServer::new(self.context.clone(), self.nodelay);
        server.run(&self.svr_cfg).await
    }

    async fn run_udp_server(&self) -> io::Result<()> {
        let udp_expiry_duration = self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60));

        let server = UdpServer::new(self.context.clone(), udp_expiry_duration, self.udp_capacity);
        server.run(&self.svr_cfg).await
    }

    async fn run_manager_report(&self) -> io::Result<()> {
        let manager_addr = self.manager_addr.as_ref().unwrap();

        loop {
            match ManagerClient::connect(
                self.context.context_ref(),
                manager_addr,
                self.context.connect_opts_ref(),
            )
            .await
            {
                Err(err) => {
                    error!("failed to connect manager {}, error: {}", manager_addr, err);
                }
                Ok(mut client) => {
                    use shadowsocks::manager::protocol::StatRequest;

                    let mut stat = HashMap::new();
                    let flow = self.flow_stat_ref();
                    stat.insert(self.svr_cfg.addr().port(), flow.tx() + flow.rx());

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
