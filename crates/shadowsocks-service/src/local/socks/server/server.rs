use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use log::{error, info};
use shadowsocks::{config::Mode, lookup_then, net::TcpListener as ShadowTcpListener, ServerAddr};
use tokio::{net::TcpStream, time};

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

#[cfg(feature = "local-socks4")]
use super::socks4::Socks4TcpHandler;
use super::socks5::{Socks5TcpHandler, Socks5UdpServer};

use crate::local::socks::config::Socks5AuthConfig;

/// SOCKS TCP server instance
pub struct SocksTcpServer {
    context: Arc<ServiceContext>,
    listener: ShadowTcpListener,
    udp_bind_addr: ServerAddr,
    balancer: PingBalancer,
    mode: Mode,
    socks5_auth: Arc<Socks5AuthConfig>,
}

impl SocksTcpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        udp_bind_addr: ServerAddr,
        balancer: PingBalancer,
        mode: Mode,
        socks5_auth: Socks5AuthConfig,
    ) -> io::Result<SocksTcpServer> {
        let listener = match client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                ShadowTcpListener::bind_with_opts(saddr, context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, port, |addr| {
                    ShadowTcpListener::bind_with_opts(&addr, context.accept_opts()).await
                })?
                .1
            }
        };
        Ok(SocksTcpServer {
            context,
            listener,
            udp_bind_addr,
            balancer,
            mode,
            socks5_auth: Arc::new(socks5_auth),
        })
    }

    /// Get TCP server local addr
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start TCP accept loop
    pub async fn run(self) -> io::Result<()> {
        info!("shadowsocks socks TCP listening on {}", self.listener.local_addr()?);

        // If UDP is enabled, SOCK5 UDP_ASSOCIATE command will let client to send requests to this address
        let udp_bind_addr = Arc::new(self.udp_bind_addr);

        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let balancer = self.balancer.clone();
            let context = self.context.clone();
            let udp_bind_addr = udp_bind_addr.clone();
            let socks5_auth = self.socks5_auth.clone();
            let mode = self.mode;

            tokio::spawn(async move {
                if let Err(err) = SocksTcpServer::handle_tcp_client(
                    context,
                    udp_bind_addr,
                    stream,
                    balancer,
                    peer_addr,
                    mode,
                    socks5_auth,
                )
                .await
                {
                    error!("socks5 tcp client handler error: {}", err);
                }
            });
        }
    }

    #[cfg(feature = "local-socks4")]
    async fn handle_tcp_client(
        context: Arc<ServiceContext>,
        udp_bind_addr: Arc<ServerAddr>,
        stream: TcpStream,
        balancer: PingBalancer,
        peer_addr: SocketAddr,
        mode: Mode,
        socks5_auth: Arc<Socks5AuthConfig>,
    ) -> io::Result<()> {
        use std::io::ErrorKind;

        let mut version_buffer = [0u8; 1];
        let n = stream.peek(&mut version_buffer).await?;
        if n == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        match version_buffer[0] {
            0x04 => {
                let handler = Socks4TcpHandler::new(context, balancer, mode);
                handler.handle_socks4_client(stream, peer_addr).await
            }

            0x05 => {
                let handler = Socks5TcpHandler::new(context, udp_bind_addr, balancer, mode, socks5_auth);
                handler.handle_socks5_client(stream, peer_addr).await
            }

            version => {
                error!("unsupported socks version {:x}", version);
                let err = io::Error::new(ErrorKind::Other, "unsupported socks version");
                Err(err)
            }
        }
    }

    #[cfg(not(feature = "local-socks4"))]
    async fn handle_tcp_client(
        context: Arc<ServiceContext>,
        udp_bind_addr: Arc<ServerAddr>,
        stream: TcpStream,
        balancer: PingBalancer,
        peer_addr: SocketAddr,
        mode: Mode,
        socks5_auth: Arc<Socks5AuthConfig>,
    ) -> io::Result<()> {
        let handler = Socks5TcpHandler::new(context, udp_bind_addr, balancer, mode, socks5_auth);
        handler.handle_socks5_client(stream, peer_addr).await
    }
}

/// SOCKS UDP server
pub type SocksUdpServer = Socks5UdpServer;
