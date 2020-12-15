//! Shadowsocks Transparent Proxy Local Server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use shadowsocks::{
    plugin::{Plugin, PluginMode},
    ServerConfig,
};

use crate::{
    config::{ClientConfig, Mode, RedirType},
    local::context::ServiceContext,
};

use super::{tcprelay::run_tcp_redir, udprelay::UdpRedir};

pub struct Redir {
    context: Arc<ServiceContext>,
    client_config: ClientConfig,
    servers: Vec<ServerConfig>,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    nodelay: bool,
    tcp_redir: RedirType,
    udp_redir: RedirType,
}

impl Redir {
    pub fn new(client_config: ClientConfig, servers: Vec<ServerConfig>) -> Redir {
        let context = ServiceContext::new();
        Redir::with_context(Arc::new(context), client_config, servers)
    }

    pub fn with_context(
        context: Arc<ServiceContext>,
        client_config: ClientConfig,
        servers: Vec<ServerConfig>,
    ) -> Redir {
        Redir {
            context,
            client_config,
            servers,
            mode: Mode::TcpOnly,
            udp_expiry_duration: None,
            udp_capacity: 256,
            nodelay: false,
            tcp_redir: RedirType::tcp_default(),
            udp_redir: RedirType::udp_default(),
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

    pub fn set_tcp_redir(&mut self, ty: RedirType) {
        self.tcp_redir = ty;
    }

    pub fn set_udp_redir(&mut self, ty: RedirType) {
        self.udp_redir = ty;
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
        run_tcp_redir(
            self.context.clone(),
            &self.client_config,
            self.servers.clone(),
            self.tcp_redir,
            self.nodelay,
        )
        .await
    }

    async fn run_udp_tunnel(&self) -> io::Result<()> {
        let mut server = UdpRedir::new(
            self.context.clone(),
            self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60)),
            self.udp_capacity,
        );
        server
            .run(&self.client_config, self.servers.clone(), self.udp_redir)
            .await
    }
}
