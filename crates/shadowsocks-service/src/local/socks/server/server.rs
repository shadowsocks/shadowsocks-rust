use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use log::{error, info};
use shadowsocks::{config::Mode, net::TcpListener as ShadowTcpListener, ServerAddr};
use tokio::{net::TcpStream, time};

#[cfg(feature = "local-http")]
use crate::local::http::HttpConnectionHandler;
use crate::local::{
    context::ServiceContext, loadbalancing::PingBalancer, net::tcp::listener::create_standard_tcp_listener,
    socks::config::Socks5AuthConfig,
};

#[cfg(feature = "local-socks4")]
use super::socks4::Socks4TcpHandler;
use super::socks5::{Socks5TcpHandler, Socks5UdpServer};

pub struct SocksTcpServerBuilder {
    context: Arc<ServiceContext>,
    client_config: ServerAddr,
    udp_associate_addr: ServerAddr,
    balancer: PingBalancer,
    mode: Mode,
    socks5_auth: Arc<Socks5AuthConfig>,
    #[cfg(target_os = "macos")]
    launchd_socket_name: Option<String>,
}

impl SocksTcpServerBuilder {
    pub(crate) fn new(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        udp_associate_addr: ServerAddr,
        balancer: PingBalancer,
        mode: Mode,
        socks5_auth: Socks5AuthConfig,
    ) -> SocksTcpServerBuilder {
        SocksTcpServerBuilder {
            context,
            client_config,
            udp_associate_addr,
            balancer,
            mode,
            socks5_auth: Arc::new(socks5_auth),
            #[cfg(target_os = "macos")]
            launchd_socket_name: None,
        }
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_socket_name(&mut self, n: String) {
        self.launchd_socket_name = Some(n);
    }

    pub async fn build(self) -> io::Result<SocksTcpServer> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                let listener = if let Some(launchd_socket_name) = self.launchd_socket_name {
                    use tokio::net::TcpListener as TokioTcpListener;
                    use crate::net::launch_activate_socket::get_launch_activate_tcp_listener;

                    let std_listener = get_launch_activate_tcp_listener(&launchd_socket_name, true)?;
                    let tokio_listener = TokioTcpListener::from_std(std_listener)?;
                    ShadowTcpListener::from_listener(tokio_listener, self.context.accept_opts())?
                } else {
                    create_standard_tcp_listener(&self.context, &self.client_config).await?
                };
            } else {
                let listener = create_standard_tcp_listener(&self.context, &self.client_config).await?;
            }
        }

        Ok(SocksTcpServer {
            context: self.context,
            listener,
            udp_associate_addr: self.udp_associate_addr,
            balancer: self.balancer,
            mode: self.mode,
            socks5_auth: self.socks5_auth,
        })
    }
}

/// SOCKS TCP server instance
pub struct SocksTcpServer {
    context: Arc<ServiceContext>,
    listener: ShadowTcpListener,
    udp_associate_addr: ServerAddr,
    balancer: PingBalancer,
    mode: Mode,
    socks5_auth: Arc<Socks5AuthConfig>,
}

impl SocksTcpServer {
    /// Get TCP server local addr
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start TCP accept loop
    pub async fn run(self) -> io::Result<()> {
        info!("shadowsocks socks TCP listening on {}", self.listener.local_addr()?);

        // If UDP is enabled, SOCK5 UDP_ASSOCIATE command will let client to send requests to this address
        let udp_associate_addr = Arc::new(self.udp_associate_addr);
        #[cfg(feature = "local-http")]
        let http_handler = HttpConnectionHandler::new(self.context.clone(), self.balancer.clone());

        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let handler = SocksTcpHandler {
                context: self.context.clone(),
                udp_associate_addr: udp_associate_addr.clone(),
                stream,
                balancer: self.balancer.clone(),
                peer_addr,
                mode: self.mode,
                socks5_auth: self.socks5_auth.clone(),
                #[cfg(feature = "local-http")]
                http_handler: http_handler.clone(),
            };

            tokio::spawn(async move {
                if let Err(err) = handler.handle_tcp_client().await {
                    error!("socks5 tcp client handler error: {}", err);
                }
            });
        }
    }
}

struct SocksTcpHandler {
    context: Arc<ServiceContext>,
    udp_associate_addr: Arc<ServerAddr>,
    stream: TcpStream,
    balancer: PingBalancer,
    peer_addr: SocketAddr,
    mode: Mode,
    socks5_auth: Arc<Socks5AuthConfig>,
    #[cfg(feature = "local-http")]
    http_handler: HttpConnectionHandler,
}

impl SocksTcpHandler {
    #[cfg(not(any(feature = "local-socks4", feature = "local-http")))]
    async fn handle_tcp_client(self) -> io::Result<()> {
        let handler = Socks5TcpHandler::new(
            self.context,
            self.udp_associate_addr,
            self.balancer,
            self.mode,
            self.socks5_auth,
        );
        handler.handle_socks5_client(self.stream, self.peer_addr).await
    }

    #[cfg(any(feature = "local-socks4", feature = "local-http"))]
    async fn handle_tcp_client(self) -> io::Result<()> {
        use std::io::ErrorKind;

        let mut version_buffer = [0u8; 1];
        let n = self.stream.peek(&mut version_buffer).await?;
        if n == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        match version_buffer[0] {
            #[cfg(feature = "local-socks4")]
            0x04 => {
                if self.socks5_auth.auth_required() {
                    error!("SOCKS4 disabled when authentication is configured");
                    Err(io::Error::new(ErrorKind::Other, "SOCKS4 unsupported"))
                } else {
                    let handler = Socks4TcpHandler::new(self.context, self.balancer, self.mode);
                    handler.handle_socks4_client(self.stream, self.peer_addr).await
                }
            }

            0x05 => {
                let handler = Socks5TcpHandler::new(
                    self.context,
                    self.udp_associate_addr,
                    self.balancer,
                    self.mode,
                    self.socks5_auth,
                );
                handler.handle_socks5_client(self.stream, self.peer_addr).await
            }

            #[cfg(feature = "local-http")]
            b'G' | b'g' | b'H' | b'h' | b'P' | b'p' | b'D' | b'd' | b'C' | b'c' | b'O' | b'o' | b'T' | b't' => {
                if self.socks5_auth.auth_required() {
                    error!("HTTP disabled when authentication is configured");
                    Err(io::Error::new(ErrorKind::Other, "HTTP unsupported"))
                } else {
                    // GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
                    match self.http_handler.serve_connection(self.stream, self.peer_addr).await {
                        Ok(..) => Ok(()),
                        Err(err) => {
                            error!("HTTP connection {} handler failed with error: {}", self.peer_addr, err);
                            Err(io::Error::new(ErrorKind::Other, err))
                        }
                    }
                }
            }

            version => {
                error!("unsupported socks version {:x}", version);
                let err = io::Error::new(ErrorKind::Other, "unsupported socks version");
                Err(err)
            }
        }
    }
}

/// SOCKS UDP server
pub type SocksUdpServer = Socks5UdpServer;
