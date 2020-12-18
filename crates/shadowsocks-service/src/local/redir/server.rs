//! Shadowsocks Transparent Proxy Local Server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use shadowsocks::ServerConfig;

use crate::{
    config::{ClientConfig, Mode, RedirType},
    local::context::ServiceContext,
};

use super::{tcprelay::run_tcp_redir, udprelay::UdpRedir};

/// Transparent Proxy
pub struct Redir {
    context: Arc<ServiceContext>,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    nodelay: bool,
    tcp_redir: RedirType,
    udp_redir: RedirType,
}

impl Redir {
    pub fn new() -> Redir {
        let context = ServiceContext::new();
        Redir::with_context(Arc::new(context))
    }

    pub fn with_context(context: Arc<ServiceContext>) -> Redir {
        Redir {
            context,
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

    pub async fn run(self, client_config: &ClientConfig, servers: &[ServerConfig]) -> io::Result<()> {
        let mut vfut = Vec::new();

        if self.mode.enable_tcp() {
            vfut.push(self.run_tcp_tunnel(client_config, servers).boxed());
        }

        if self.mode.enable_udp() {
            vfut.push(self.run_udp_tunnel(client_config, servers).boxed());
        }

        let _ = future::select_all(vfut).await;

        let err = io::Error::new(ErrorKind::Other, "tunnel server exited unexpectly");
        Err(err)
    }

    async fn run_tcp_tunnel(&self, client_config: &ClientConfig, servers: &[ServerConfig]) -> io::Result<()> {
        run_tcp_redir(
            self.context.clone(),
            client_config,
            servers,
            self.tcp_redir,
            self.nodelay,
        )
        .await
    }

    async fn run_udp_tunnel(&self, client_config: &ClientConfig, servers: &[ServerConfig]) -> io::Result<()> {
        let mut server = UdpRedir::new(
            self.context.clone(),
            self.udp_redir,
            self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60)),
            self.udp_capacity,
        );
        server.run(client_config, servers).await
    }
}
