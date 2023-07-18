//! Shadowsocks SOCKS Local Server

use std::{io, sync::Arc, time::Duration};

use futures::{future, FutureExt};
use shadowsocks::{config::Mode, ServerAddr};

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

pub use self::server::{SocksTcpServer, SocksUdpServer};
use self::socks5::Socks5UdpServer;

use super::config::Socks5AuthConfig;

#[allow(clippy::module_inception)]
mod server;
#[cfg(feature = "local-socks4")]
mod socks4;
mod socks5;

/// SOCKS4/4a, SOCKS5 Local Server builder
pub struct SocksBuilder {
    context: Arc<ServiceContext>,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    udp_bind_addr: Option<ServerAddr>,
    socks5_auth: Socks5AuthConfig,
    client_config: ServerAddr,
    balancer: PingBalancer,
}

impl SocksBuilder {
    /// Create a new SOCKS server with default configuration
    pub fn new(client_config: ServerAddr, balancer: PingBalancer) -> SocksBuilder {
        let context = ServiceContext::new();
        SocksBuilder::with_context(Arc::new(context), client_config, balancer)
    }

    /// Create a new SOCKS server with context
    pub fn with_context(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        balancer: PingBalancer,
    ) -> SocksBuilder {
        SocksBuilder {
            context,
            mode: Mode::TcpOnly,
            udp_expiry_duration: None,
            udp_capacity: None,
            udp_bind_addr: None,
            socks5_auth: Socks5AuthConfig::default(),
            client_config,
            balancer,
        }
    }

    /// Set server mode
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Set UDP association's expiry duration
    pub fn set_udp_expiry_duration(&mut self, d: Duration) {
        self.udp_expiry_duration = Some(d);
    }

    /// Set total UDP association to be kept simultaneously in server
    pub fn set_udp_capacity(&mut self, c: usize) {
        self.udp_capacity = Some(c);
    }

    /// UDP server's bind address
    ///
    /// * If `mode` is `tcp_only`, then it will still return this address for `UDP_ASSOCIATE` command
    /// * Otherwise, UDP relay will bind to this address
    pub fn set_udp_bind_addr(&mut self, a: ServerAddr) {
        self.udp_bind_addr = Some(a);
    }

    /// Set SOCKS5 Username/Password Authentication configuration
    pub fn set_socks5_auth(&mut self, p: Socks5AuthConfig) {
        self.socks5_auth = p;
    }

    pub async fn build(self) -> io::Result<Socks> {
        let udp_bind_addr = self.udp_bind_addr.unwrap_or_else(|| self.client_config.clone());

        let mut udp_server = None;
        if self.mode.enable_udp() {
            let server = Socks5UdpServer::new(
                self.context.clone(),
                &udp_bind_addr,
                self.udp_expiry_duration,
                self.udp_capacity,
                self.balancer.clone(),
            )
            .await?;
            udp_server = Some(server);
        }

        let mut tcp_server = None;
        if self.mode.enable_tcp() {
            let server = SocksTcpServer::new(
                self.context.clone(),
                self.client_config,
                udp_bind_addr,
                self.balancer.clone(),
                self.mode,
                self.socks5_auth,
            )
            .await?;
            tcp_server = Some(server);
        }

        Ok(Socks { tcp_server, udp_server })
    }
}

/// SOCKS4/4a, SOCKS5 Local Server
pub struct Socks {
    tcp_server: Option<SocksTcpServer>,
    udp_server: Option<SocksUdpServer>,
}

impl Socks {
    /// TCP server instance
    pub fn tcp_server(&self) -> Option<&SocksTcpServer> {
        self.tcp_server.as_ref()
    }

    /// UDP server instance
    pub fn udp_server(&self) -> Option<&SocksUdpServer> {
        self.udp_server.as_ref()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        let mut vfut = Vec::new();

        if let Some(tcp_server) = self.tcp_server {
            vfut.push(tcp_server.run().boxed());
        }

        if let Some(udp_server) = self.udp_server {
            // NOTE: SOCKS 5 RFC requires TCP handshake for UDP ASSOCIATE command
            // But here we can start a standalone UDP SOCKS 5 relay server, for special use cases
            vfut.push(udp_server.run().boxed());
        }

        let (res, ..) = future::select_all(vfut).await;
        res
    }
}
