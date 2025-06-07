//! Shadowsocks Transparent Proxy Local Server

use std::{io, sync::Arc, time::Duration};

use futures::{FutureExt, future};
use shadowsocks::{ServerAddr, config::Mode};

use crate::{
    config::RedirType,
    local::{context::ServiceContext, loadbalancing::PingBalancer},
};

use super::{tcprelay::RedirTcpServer, udprelay::RedirUdpServer};

/// Transparent Proxy builder
pub struct RedirBuilder {
    context: Arc<ServiceContext>,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    tcp_redir: RedirType,
    udp_redir: RedirType,
    client_addr: ServerAddr,
    udp_bind_addr: Option<ServerAddr>,
    balancer: PingBalancer,
}

impl RedirBuilder {
    /// Create a new transparent proxy server with default configuration
    pub fn new(client_addr: ServerAddr, balancer: PingBalancer) -> Self {
        let context = ServiceContext::new();
        Self::with_context(Arc::new(context), client_addr, balancer)
    }

    /// Create a new transparent proxy server with context
    pub fn with_context(context: Arc<ServiceContext>, client_addr: ServerAddr, balancer: PingBalancer) -> Self {
        Self {
            context,
            mode: Mode::TcpOnly,
            udp_expiry_duration: None,
            udp_capacity: None,
            tcp_redir: RedirType::tcp_default(),
            udp_redir: RedirType::udp_default(),
            client_addr,
            udp_bind_addr: None,
            balancer,
        }
    }

    /// Set UDP association's expiry duration
    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    /// Set total UDP association to be kept simultaneously in server
    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = Some(c);
    }

    /// Set server mode
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Set transparent proxy type of TCP relay, which is platform dependent
    pub fn set_tcp_redir(&mut self, ty: RedirType) {
        self.tcp_redir = ty;
    }

    /// Set transparent proxy type of UDP relay, which is platform dependent
    pub fn set_udp_redir(&mut self, ty: RedirType) {
        self.udp_redir = ty;
    }

    /// Set UDP bind address
    pub fn set_udp_bind_addr(&mut self, addr: ServerAddr) {
        self.udp_bind_addr = Some(addr);
    }

    pub async fn build(self) -> io::Result<Redir> {
        let mut tcp_server = None;
        if self.mode.enable_tcp() {
            let server = RedirTcpServer::new(
                self.context.clone(),
                &self.client_addr,
                self.balancer.clone(),
                self.tcp_redir,
            )
            .await?;
            tcp_server = Some(server);
        }

        let mut udp_server = None;
        if self.mode.enable_udp() {
            let udp_addr = self.udp_bind_addr.as_ref().unwrap_or(&self.client_addr);

            let server = RedirUdpServer::new(
                self.context,
                self.udp_redir,
                udp_addr,
                self.udp_expiry_duration,
                self.udp_capacity,
                self.balancer,
            )
            .await?;
            udp_server = Some(server);
        }

        Ok(Redir { tcp_server, udp_server })
    }
}

/// Transparent Proxy
pub struct Redir {
    tcp_server: Option<RedirTcpServer>,
    udp_server: Option<RedirUdpServer>,
}

impl Redir {
    /// TCP server instance
    pub fn tcp_server(&self) -> Option<&RedirTcpServer> {
        self.tcp_server.as_ref()
    }

    /// UDP server instance
    pub fn udp_server(&self) -> Option<&RedirUdpServer> {
        self.udp_server.as_ref()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        let mut vfut = Vec::new();

        if let Some(tcp_server) = self.tcp_server {
            vfut.push(tcp_server.run().boxed());
        }

        if let Some(udp_server) = self.udp_server {
            vfut.push(udp_server.run().boxed());
        }

        let (res, ..) = future::select_all(vfut).await;
        res
    }
}
