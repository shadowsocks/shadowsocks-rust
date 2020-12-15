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
    lookup_then,
    plugin::{Plugin, PluginMode},
    ServerConfig,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    config::{ClientConfig, Mode},
    local::{
        context::ServiceContext,
        loadbalancing::{BasicServerIdent, PingBalancerBuilder, ServerType as BalancerServerType},
    },
};

#[cfg(feature = "local-socks4")]
use self::socks4::Socks4TcpHandler;
use self::socks5::{Socks5TcpHandler, Socks5UdpServer};

#[cfg(feature = "local-socks4")]
mod socks4;
mod socks5;

pub struct Socks {
    context: Arc<ServiceContext>,
    client_config: Arc<ClientConfig>,
    servers: Vec<ServerConfig>,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    nodelay: bool,
}

impl Socks {
    pub fn new(client_config: ClientConfig, servers: Vec<ServerConfig>) -> Socks {
        let context = ServiceContext::new();
        Socks::with_context(Arc::new(context), client_config, servers)
    }

    pub fn with_context(
        context: Arc<ServiceContext>,
        client_config: ClientConfig,
        servers: Vec<ServerConfig>,
    ) -> Socks {
        Socks {
            context,
            client_config: Arc::new(client_config),
            servers,
            mode: Mode::TcpOnly,
            udp_expiry_duration: None,
            udp_capacity: 256,
            nodelay: false,
        }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
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

            vfut.push(self.run_tcp_server().boxed());
        }

        if self.mode.enable_udp() {
            vfut.push(self.run_udp_server().boxed());
        }

        let _ = future::select_all(vfut).await;

        let err = io::Error::new(ErrorKind::Other, "socks server exited unexpectly");
        Err(err)
    }

    async fn run_tcp_server(&self) -> io::Result<()> {
        let listener = match *self.client_config {
            ClientConfig::SocketAddr(ref saddr) => TcpListener::bind(saddr).await?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |addr| {
                    TcpListener::bind(addr).await
                })?
                .1
            }
        };

        info!("shadowsocks socks listening on {}", self.client_config);

        let mut balancer_builder = PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Tcp);

        for server in &self.servers {
            let server_ident = BasicServerIdent::new(server.clone());
            balancer_builder.add_server(server_ident);
        }

        let (balancer, checker) = balancer_builder.build();
        tokio::spawn(checker);

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
            let nodelay = self.nodelay;
            let client_config = self.client_config.clone();
            let mode = self.mode;

            tokio::spawn(Socks::handle_tcp_client(
                context,
                client_config,
                mode,
                stream,
                server,
                peer_addr,
                nodelay,
            ));
        }
    }

    #[cfg(feature = "local-socks4")]
    async fn handle_tcp_client(
        context: Arc<ServiceContext>,
        client_config: Arc<ClientConfig>,
        mode: Mode,
        stream: TcpStream,
        server: Arc<BasicServerIdent>,
        peer_addr: SocketAddr,
        nodelay: bool,
    ) -> io::Result<()> {
        let mut version_buffer = [0u8; 1];
        let n = stream.peek(&mut version_buffer).await?;
        if n == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        match version_buffer[0] {
            0x04 => {
                let handler = Socks4TcpHandler::new(context, mode, nodelay, server);
                handler.handle_socks4_client(stream, peer_addr).await
            }

            0x05 => {
                let handler = Socks5TcpHandler::new(context, client_config, mode, nodelay, server);
                handler.handle_socks5_client(stream, peer_addr).await
            }

            version => {
                error!("unsupported socks version {:x}", version);
                let err = io::Error::new(ErrorKind::Other, "unsupported socks version");
                return Err(err);
            }
        }
    }

    #[cfg(not(feature = "local-socks4"))]
    async fn handle_tcp_client(
        context: Arc<ServiceContext>,
        client_config: Arc<ClientConfig>,
        mode: Mode,
        stream: TcpStream,
        server: Arc<BasicServerIdent>,
        peer_addr: SocketAddr,
        nodelay: bool,
    ) -> io::Result<()> {
        let handler = Socks5TcpHandler::new(context, client_config, mode, nodelay, server);
        handler.handle_socks5_client(stream, peer_addr).await
    }

    async fn run_udp_server(&self) -> io::Result<()> {
        let mut server = Socks5UdpServer::new(
            self.context.clone(),
            self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60)),
            self.udp_capacity,
        );
        server.run(&self.client_config, self.servers.clone()).await
    }
}
