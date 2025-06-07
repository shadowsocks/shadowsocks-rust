//! Shadowsocks Local Tunnel Server

use std::{io, sync::Arc, time::Duration};

use futures::{FutureExt, future};
use shadowsocks::{ServerAddr, config::Mode, relay::socks5::Address};

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

use super::{
    tcprelay::{TunnelTcpServer, TunnelTcpServerBuilder},
    udprelay::{TunnelUdpServer, TunnelUdpServerBuilder},
};

pub struct TunnelBuilder {
    context: Arc<ServiceContext>,
    forward_addr: Address,
    mode: Mode,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    client_addr: ServerAddr,
    udp_addr: Option<ServerAddr>,
    balancer: PingBalancer,
    #[cfg(target_os = "macos")]
    launchd_tcp_socket_name: Option<String>,
    #[cfg(target_os = "macos")]
    launchd_udp_socket_name: Option<String>,
}

impl TunnelBuilder {
    /// Create a new Tunnel server forwarding to `forward_addr`
    pub fn new(forward_addr: Address, client_addr: ServerAddr, balancer: PingBalancer) -> Self {
        let context = ServiceContext::new();
        Self::with_context(Arc::new(context), forward_addr, client_addr, balancer)
    }

    /// Create a new Tunnel server with context
    pub fn with_context(
        context: Arc<ServiceContext>,
        forward_addr: Address,
        client_addr: ServerAddr,
        balancer: PingBalancer,
    ) -> Self {
        Self {
            context,
            forward_addr,
            mode: Mode::TcpOnly,
            udp_expiry_duration: None,
            udp_capacity: None,
            client_addr,
            udp_addr: None,
            balancer,
            #[cfg(target_os = "macos")]
            launchd_tcp_socket_name: None,
            #[cfg(target_os = "macos")]
            launchd_udp_socket_name: None,
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

    /// Set UDP bind address
    pub fn set_udp_bind_addr(&mut self, addr: ServerAddr) {
        self.udp_addr = Some(addr);
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_tcp_socket_name(&mut self, n: String) {
        self.launchd_tcp_socket_name = Some(n);
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_udp_socket_name(&mut self, n: String) {
        self.launchd_udp_socket_name = Some(n);
    }

    pub async fn build(self) -> io::Result<Tunnel> {
        let mut tcp_server = None;
        if self.mode.enable_tcp() {
            #[allow(unused_mut)]
            let mut builder = TunnelTcpServerBuilder::new(
                self.context.clone(),
                self.client_addr.clone(),
                self.balancer.clone(),
                self.forward_addr.clone(),
            );

            #[cfg(target_os = "macos")]
            if let Some(s) = self.launchd_tcp_socket_name {
                builder.set_launchd_socket_name(s);
            }

            let server = builder.build().await?;
            tcp_server = Some(server);
        }

        let mut udp_server = None;
        if self.mode.enable_udp() {
            let udp_addr = self.udp_addr.unwrap_or(self.client_addr);

            #[allow(unused_mut)]
            let mut builder = TunnelUdpServerBuilder::new(
                self.context.clone(),
                udp_addr,
                self.udp_expiry_duration,
                self.udp_capacity,
                self.balancer,
                self.forward_addr,
            );

            #[cfg(target_os = "macos")]
            if let Some(s) = self.launchd_udp_socket_name {
                builder.set_launchd_socket_name(s);
            }

            let server = builder.build().await?;
            udp_server = Some(server);
        }

        Ok(Tunnel { tcp_server, udp_server })
    }
}

/// Tunnel Server
pub struct Tunnel {
    tcp_server: Option<TunnelTcpServer>,
    udp_server: Option<TunnelUdpServer>,
}

impl Tunnel {
    /// TCP server instance
    pub fn tcp_server(&self) -> Option<&TunnelTcpServer> {
        self.tcp_server.as_ref()
    }

    /// UDP server instance
    pub fn udp_server(&self) -> Option<&TunnelUdpServer> {
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
