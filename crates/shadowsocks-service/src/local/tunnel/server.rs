//! Shadowsocks Local Tunnel Server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use shadowsocks::{
    plugin::{Plugin, PluginMode},
    relay::socks5::Address,
    ServerConfig,
};

use crate::{
    config::{ClientConfig, Mode},
    local::context::ServiceContext,
};

use super::{tcprelay::run_tcp_tunnel, udprelay::UdpTunnel};

pub struct Tunnel {
    context: Arc<ServiceContext>,
    client_config: ClientConfig,
    servers: Vec<ServerConfig>,
    forward_addr: Address,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    nodelay: bool,
}

impl Tunnel {
    pub fn new(client_config: ClientConfig, servers: Vec<ServerConfig>, forward_addr: Address) -> Tunnel {
        let context = ServiceContext::new();
        Tunnel::with_context(Arc::new(context), client_config, servers, forward_addr)
    }

    pub fn with_context(
        context: Arc<ServiceContext>,
        client_config: ClientConfig,
        servers: Vec<ServerConfig>,
        forward_addr: Address,
    ) -> Tunnel {
        Tunnel {
            context,
            client_config,
            servers,
            forward_addr,
            mode: Mode::TcpOnly,
            udp_expiry_duration: None,
            udp_capacity: 256,
            nodelay: false,
        }
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
        run_tcp_tunnel(
            self.context.clone(),
            &self.client_config,
            self.servers.clone(),
            &self.forward_addr,
            self.nodelay,
        )
        .await
    }

    async fn run_udp_tunnel(&self) -> io::Result<()> {
        let mut server = UdpTunnel::new(
            self.context.clone(),
            self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60)),
            self.udp_capacity,
        );
        server
            .run(&self.client_config, self.servers.clone(), &self.forward_addr)
            .await
    }
}
