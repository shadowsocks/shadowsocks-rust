//! Shadowsocks Server instance

use std::{collections::HashMap, io, sync::Arc, time::Duration};

use futures::future;
use log::{error, trace};
use shadowsocks::{
    ManagerClient,
    config::{ManagerAddr, ServerConfig},
    dns_resolver::DnsResolver,
    net::{AcceptOpts, ConnectOpts},
    plugin::{Plugin, PluginMode},
};
use tokio::time;

use crate::{acl::AccessControl, config::SecurityConfig, net::FlowStat, utils::ServerHandle};

use super::{context::ServiceContext, tcprelay::TcpServer, udprelay::UdpServer};

/// Shadowsocks Server Builder
pub struct ServerBuilder {
    context: ServiceContext,
    svr_cfg: ServerConfig,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    manager_addr: Option<ManagerAddr>,
    accept_opts: AcceptOpts,
}

impl ServerBuilder {
    /// Create a new server builder from configuration
    pub fn new(svr_cfg: ServerConfig) -> Self {
        Self::with_context(ServiceContext::new(), svr_cfg)
    }

    /// Create a new server builder with context
    fn with_context(context: ServiceContext, svr_cfg: ServerConfig) -> Self {
        Self {
            context,
            svr_cfg,
            udp_expiry_duration: None,
            udp_capacity: None,
            manager_addr: None,
            accept_opts: AcceptOpts::default(),
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
        self.context.set_connect_opts(opts)
    }

    /// Set UDP association's expiry duration
    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    /// Set total UDP associations to be kept in one server
    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = Some(c);
    }

    /// Set manager's address to report `stat`
    pub fn set_manager_addr(&mut self, manager_addr: ManagerAddr) {
        self.manager_addr = Some(manager_addr);
    }

    /// Get server's configuration
    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    /// Set customized DNS resolver
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        self.context.set_dns_resolver(resolver)
    }

    /// Set access control list
    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        self.context.set_acl(acl);
    }

    /// Set `AcceptOpts` for accepting new connections
    pub fn set_accept_opts(&mut self, opts: AcceptOpts) {
        self.accept_opts = opts;
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        self.context.set_ipv6_first(ipv6_first);
    }

    /// Set security config
    pub fn set_security_config(&mut self, security: &SecurityConfig) {
        self.context.set_security_config(security)
    }

    /// Start the server
    ///
    /// 1. Starts plugin (subprocess)
    /// 2. Starts TCP server (listener)
    /// 3. Starts UDP server (listener)
    pub async fn build(mut self) -> io::Result<Server> {
        let context = Arc::new(self.context);

        let mut plugin = None;

        if let Some(plugin_cfg) = self.svr_cfg.plugin() {
            let plugin_process = Plugin::start(plugin_cfg, self.svr_cfg.addr(), PluginMode::Server)?;
            self.svr_cfg.set_plugin_addr(plugin_process.local_addr().into());
            plugin = Some(plugin_process);
        }

        let mut tcp_server = None;
        if self.svr_cfg.mode().enable_tcp() {
            let server = TcpServer::new(context.clone(), self.svr_cfg.clone(), self.accept_opts.clone()).await?;
            tcp_server = Some(server);
        }

        let mut udp_server = None;
        if self.svr_cfg.mode().enable_udp() {
            let server = UdpServer::new(
                context.clone(),
                self.svr_cfg.clone(),
                self.udp_expiry_duration,
                self.udp_capacity,
                self.accept_opts.clone(),
            )
            .await?;
            udp_server = Some(server);
        }

        Ok(Server {
            context,
            svr_cfg: self.svr_cfg,
            tcp_server,
            udp_server,
            manager_addr: self.manager_addr,
            plugin,
        })
    }
}

/// Shadowsocks Server instance
pub struct Server {
    context: Arc<ServiceContext>,
    svr_cfg: ServerConfig,
    tcp_server: Option<TcpServer>,
    udp_server: Option<UdpServer>,
    manager_addr: Option<ManagerAddr>,
    plugin: Option<Plugin>,
}

impl Server {
    /// Get Server's configuration
    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    /// Get TCP server instance
    pub fn tcp_server(&self) -> Option<&TcpServer> {
        self.tcp_server.as_ref()
    }

    /// Get UDP server instance
    pub fn udp_server(&self) -> Option<&UdpServer> {
        self.udp_server.as_ref()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        let mut vfut = Vec::new();

        if let Some(plugin) = self.plugin {
            vfut.push(ServerHandle(tokio::spawn(async move {
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
            })));
        }

        if let Some(tcp_server) = self.tcp_server {
            vfut.push(ServerHandle(tokio::spawn(tcp_server.run())));
        }

        if let Some(udp_server) = self.udp_server {
            vfut.push(ServerHandle(tokio::spawn(udp_server.run())));
        }

        if let Some(manager_addr) = self.manager_addr {
            vfut.push(ServerHandle(tokio::spawn(async move {
                loop {
                    match ManagerClient::connect(
                        self.context.context_ref(),
                        &manager_addr,
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
                            let flow = self.context.flow_stat_ref();
                            stat.insert(self.svr_cfg.addr().port(), flow.tx() + flow.rx());

                            let req = StatRequest { stat };

                            match client.stat(&req).await {
                                Err(err) => {
                                    error!(
                                        "failed to send stat to manager {}, error: {}, {:?}",
                                        manager_addr, err, req
                                    );
                                }
                                _ => {
                                    trace!("report to manager {}, {:?}", manager_addr, req);
                                }
                            }
                        }
                    }

                    // Report every 10 seconds
                    time::sleep(Duration::from_secs(10)).await;
                }
            })));
        }

        if let (Err(err), ..) = future::select_all(vfut).await {
            error!("servers exited with error: {}", err);
        }

        let err = io::Error::other("server exited unexpectedly");
        Err(err)
    }
}
