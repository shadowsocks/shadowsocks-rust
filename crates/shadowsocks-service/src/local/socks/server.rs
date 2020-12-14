//! Shadowsocks SOCKS Local Server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use log::{error, info};
use shadowsocks::{
    config::ServerType,
    context::{Context, SharedContext},
    dns_resolver::DnsResolver,
    lookup_then,
    net::ConnectOpts,
    plugin::{Plugin, PluginMode},
    ServerConfig,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    config::ClientConfig,
    local::{
        acl::AccessControl,
        loadbalancing::{BasicServerIdent, PingBalancerBuilder, ServerType as BalancerServerType},
    },
    net::FlowStat,
};

use super::{socks4_server::Socks4, socks5_server::Socks5};

pub struct Socks {
    context: SharedContext,
    flow_stat: Arc<FlowStat>,
    client_config: ClientConfig,
    servers: Vec<ServerConfig>,
    connect_opts: Arc<ConnectOpts>,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    nodelay: bool,
    acl: Option<Arc<AccessControl>>,
}

impl Socks {
    pub fn new(client_config: ClientConfig, servers: Vec<ServerConfig>) -> Socks {
        let context = Context::new_shared(ServerType::Server);
        Socks::with_context(context, client_config, servers)
    }

    fn with_context(context: SharedContext, client_config: ClientConfig, servers: Vec<ServerConfig>) -> Socks {
        Socks {
            context,
            flow_stat: Arc::new(FlowStat::new()),
            client_config,
            servers,
            connect_opts: Arc::new(ConnectOpts::default()),
            udp_expiry_duration: None,
            udp_capacity: 256,
            nodelay: false,
            acl: None,
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

        for server in &mut self.servers {
            if let Some(c) = server.plugin() {
                let plugin = Plugin::start(c, server.addr(), PluginMode::Client)?;
                server.set_plugin_addr(plugin.local_addr().into());
                vfut.push(async move { plugin.join().map(|r| r.map(|_| ())).await }.boxed());
            }
        }

        vfut.push(self.run_socks_server().boxed());

        let _ = future::select_all(vfut).await;

        let err = io::Error::new(ErrorKind::Other, "socks5 server exited unexpectly");
        Err(err)
    }

    async fn run_socks_server(self) -> io::Result<()> {
        let listener = match self.client_config {
            ClientConfig::SocketAddr(ref saddr) => TcpListener::bind(saddr).await?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(&self.context, dname, port, |addr| { TcpListener::bind(addr).await })?.1
            }
        };

        info!("shadowsocks socks listening on {}", self.client_config);

        let mut balancer_builder =
            PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Tcp, self.connect_opts.clone());

        for server in self.servers {
            let server_ident = BasicServerIdent::new(server);
            balancer_builder.add_server(server_ident);
        }

        let (balancer, checker) = balancer_builder.build();
        tokio::spawn(checker);

        let client_config = Arc::new(self.client_config);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if self.nodelay {
                let _ = stream.set_nodelay(true);
            }

            let server = balancer.best_server();
            let context = self.context.clone();
            let connect_opts = self.connect_opts.clone();
            let flow_stat = self.flow_stat.clone();
            let nodelay = self.nodelay;
            let client_config = client_config.clone();
            let acl = self.acl.clone();

            tokio::spawn(Socks::handle_tcp_client(
                context,
                client_config,
                stream,
                server,
                peer_addr,
                connect_opts,
                flow_stat,
                nodelay,
                acl,
            ));
        }
    }

    async fn handle_tcp_client(
        context: SharedContext,
        client_config: Arc<ClientConfig>,
        stream: TcpStream,
        server: Arc<BasicServerIdent>,
        peer_addr: SocketAddr,
        connect_opts: Arc<ConnectOpts>,
        flow_stat: Arc<FlowStat>,
        nodelay: bool,
        acl: Option<Arc<AccessControl>>,
    ) -> io::Result<()> {
        let mut version_buffer = [0u8; 1];
        let n = stream.peek(&mut version_buffer).await?;
        if n == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        match version_buffer[0] {
            0x04 => {
                let handler = Socks4::new(context, flow_stat, connect_opts, nodelay, acl);
                handler.handle_socks4_client(stream, server, peer_addr).await
            }

            0x05 => {
                let handler = Socks5::new(context, flow_stat, connect_opts, nodelay, acl);
                handler
                    .handle_socks5_client(&client_config, stream, server, peer_addr)
                    .await
            }

            version => {
                error!("unsupported socks version {:x}", version);
                let err = io::Error::new(ErrorKind::Other, "unsupported socks version");
                return Err(err);
            }
        }
    }
}
