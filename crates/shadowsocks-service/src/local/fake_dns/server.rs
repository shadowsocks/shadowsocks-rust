//! Fake DNS server

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use futures::{future, FutureExt};
use ipnet::{Ipv4Net, Ipv6Net};
use shadowsocks::config::{Mode, ServerAddr};

use crate::local::context::ServiceContext;

use super::{manager::FakeDnsManager, tcp_server::FakeDnsTcpServer, udp_server::FakeDnsUdpServer};

/// Fake DNS builder
pub struct FakeDnsBuilder {
    context: Arc<ServiceContext>,
    mode: Mode,
    client_addr: ServerAddr,
    database_path: PathBuf,
    ipv4_network: Ipv4Net,
    ipv6_network: Ipv6Net,
    expire_duration: Duration,
}

impl FakeDnsBuilder {
    /// Create a new Fake DNS server
    pub fn new(client_addr: ServerAddr) -> FakeDnsBuilder {
        let context = ServiceContext::new();
        FakeDnsBuilder::with_context(Arc::new(context), client_addr)
    }

    /// Create a new Fake DNS server with context
    pub fn with_context(context: Arc<ServiceContext>, client_addr: ServerAddr) -> FakeDnsBuilder {
        FakeDnsBuilder {
            context,
            mode: Mode::TcpAndUdp,
            client_addr,
            database_path: "shadowsocks-fakedns.sled".into(),
            ipv4_network: Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
            ipv6_network: Ipv6Net::new(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7).unwrap(),
            expire_duration: Duration::from_secs(10),
        }
    }

    /// Set IPv4 network
    pub fn set_ipv4_network(&mut self, ipv4_network: Ipv4Net) {
        self.ipv4_network = ipv4_network;
    }

    /// Set IPv6 network
    pub fn set_ipv6_network(&mut self, ipv6_network: Ipv6Net) {
        self.ipv6_network = ipv6_network;
    }

    /// Set expire duration
    pub fn set_expire_duration(&mut self, expire: Duration) {
        self.expire_duration = expire;
    }

    /// Set database path
    pub fn set_database_path<P: AsRef<Path>>(&mut self, database_path: P) {
        self.database_path = database_path.as_ref().to_path_buf();
    }

    /// Build Fake DNS server
    pub async fn build(self) -> io::Result<FakeDns> {
        let manager = FakeDnsManager::open(
            &self.database_path,
            self.ipv4_network,
            self.ipv6_network,
            self.expire_duration,
        )?;
        let manager = Arc::new(manager);

        let mut tcp_server = None;
        if self.mode.enable_tcp() {
            let server = FakeDnsTcpServer::new(self.context.clone(), &self.client_addr, manager.clone()).await?;
            tcp_server = Some(server);
        }

        let mut udp_server = None;
        if self.mode.enable_udp() {
            let server = FakeDnsUdpServer::new(self.context.clone(), &self.client_addr, manager.clone()).await?;
            udp_server = Some(server);
        }

        Ok(FakeDns {
            tcp_server,
            udp_server,
            manager,
        })
    }
}

/// Fake DNS server instance
pub struct FakeDns {
    tcp_server: Option<FakeDnsTcpServer>,
    udp_server: Option<FakeDnsUdpServer>,
    manager: Arc<FakeDnsManager>,
}

impl FakeDns {
    /// TCP Server instance
    pub fn tcp_server(&self) -> Option<&FakeDnsTcpServer> {
        self.tcp_server.as_ref()
    }

    /// UDP Server instance
    pub fn udp_server(&self) -> Option<&FakeDnsUdpServer> {
        self.udp_server.as_ref()
    }

    /// Get the manager
    pub fn clone_manager(&self) -> Arc<FakeDnsManager> {
        self.manager.clone()
    }

    /// Run server
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
