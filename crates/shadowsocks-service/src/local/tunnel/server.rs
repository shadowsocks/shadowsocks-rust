//! Shadowsocks Local Tunnel Server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
    net::ConnectOpts,
    plugin::{Plugin, PluginMode},
    relay::socks5::Address,
    ServerConfig,
};
use trust_dns_resolver::TokioAsyncResolver;

use crate::{
    config::{ClientConfig, Mode},
    net::FlowStat,
};

use super::{tcprelay::TcpTunnel, udprelay::UdpTunnel};

pub struct Tunnel {
    context: SharedContext,
    flow_stat: Arc<FlowStat>,
    client_config: ClientConfig,
    servers: Vec<ServerConfig>,
    forward_addr: Address,
    mode: Mode,
    connect_opts: Arc<ConnectOpts>,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    nodelay: bool,
}

impl Tunnel {
    pub fn new(client_config: ClientConfig, servers: Vec<ServerConfig>, forward_addr: Address) -> Tunnel {
        let context = Context::new_shared(ServerType::Server);
        Tunnel::with_context(context, client_config, servers, forward_addr)
    }

    fn with_context(
        context: SharedContext,
        client_config: ClientConfig,
        servers: Vec<ServerConfig>,
        forward_addr: Address,
    ) -> Tunnel {
        Tunnel {
            context,
            flow_stat: Arc::new(FlowStat::new()),
            client_config,
            servers,
            forward_addr,
            mode: Mode::TcpOnly,
            connect_opts: Arc::new(ConnectOpts::default()),
            udp_expiry_duration: None,
            udp_capacity: 256,
            nodelay: false,
        }
    }

    pub fn flow_stat(&self) -> &Arc<FlowStat> {
        &self.flow_stat
    }

    pub fn set_connect_opts(&mut self, opts: Arc<ConnectOpts>) {
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

    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    #[cfg(feature = "trust-dns")]
    pub fn set_dns_resolver(&mut self, resolver: Arc<TokioAsyncResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    pub async fn run(mut self) -> io::Result<()> {
        let mut vfut = Vec::new();

        if self.mode.enable_tcp() {
            for server in &mut self.servers {
                if let Some(c) = server.plugin() {
                    let plugin = Plugin::start(c, server.addr(), PluginMode::Client)?;
                    server.set_plugin_addr(plugin.local_addr().into());
                    vfut.push(async move { plugin.join().map(|r| r.map(|_| ())).await }.boxed());
                }
            }
            vfut.push(self.run_tcp_tunnel().boxed());
        }

        if self.mode.enable_udp() {
            vfut.push(self.run_udp_tunnel().boxed());
        }

        let _ = future::select_all(vfut).await;

        let err = io::Error::new(ErrorKind::Other, "tunnel server exited unexpectly");
        Err(err)
    }

    async fn run_tcp_tunnel(&self) -> io::Result<()> {
        let server = TcpTunnel::new(
            self.context.clone(),
            self.flow_stat.clone(),
            self.connect_opts.clone(),
            self.nodelay,
        );
        server
            .run(&self.client_config, self.servers.clone(), &self.forward_addr)
            .await
    }

    async fn run_udp_tunnel(&self) -> io::Result<()> {
        let mut server = UdpTunnel::new(
            self.context.clone(),
            self.flow_stat.clone(),
            self.connect_opts.clone(),
            self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60)),
            self.udp_capacity,
        );
        server
            .run(&self.client_config, self.servers.clone(), &self.forward_addr)
            .await
    }
}
