//! Shadowsocks Local Tunnel Server

use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use shadowsocks::{relay::socks5::Address, ServerConfig};

use crate::{
    config::{ClientConfig, Mode},
    local::context::ServiceContext,
};

use super::{tcprelay::run_tcp_tunnel, udprelay::UdpTunnel};

/// Tunnel Server
pub struct Tunnel {
    context: Arc<ServiceContext>,
    forward_addr: Address,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: usize,
    nodelay: bool,
}

impl Tunnel {
    pub fn new(forward_addr: Address) -> Tunnel {
        let context = ServiceContext::new();
        Tunnel::with_context(Arc::new(context), forward_addr)
    }

    pub fn with_context(context: Arc<ServiceContext>, forward_addr: Address) -> Tunnel {
        Tunnel {
            context,
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
        run_tcp_tunnel(
            self.context.clone(),
            client_config,
            servers,
            &self.forward_addr,
            self.nodelay,
        )
        .await
    }

    async fn run_udp_tunnel(&self, client_config: &ClientConfig, servers: &[ServerConfig]) -> io::Result<()> {
        let mut server = UdpTunnel::new(
            self.context.clone(),
            self.udp_expiry_duration.unwrap_or(Duration::from_secs(5 * 60)),
            self.udp_capacity,
        );
        server.run(client_config, servers, &self.forward_addr).await
    }
}
