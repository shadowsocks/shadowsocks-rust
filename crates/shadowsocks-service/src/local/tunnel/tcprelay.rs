//! TCP Tunnel Server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use log::{error, info, trace};
use shadowsocks::{ServerAddr, net::TcpListener as ShadowTcpListener, relay::socks5::Address};
use tokio::{net::TcpStream, time};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::{AutoProxyClientStream, tcp::listener::create_standard_tcp_listener},
    utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
};

pub struct TunnelTcpServerBuilder {
    context: Arc<ServiceContext>,
    client_config: ServerAddr,
    balancer: PingBalancer,
    forward_addr: Option<Address>,
    #[cfg(target_os = "macos")]
    launchd_socket_name: Option<String>,
}

impl TunnelTcpServerBuilder {
    pub(crate) fn new(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        balancer: PingBalancer,
        forward_addr: Option<Address>,
    ) -> Self {
        Self {
            context,
            client_config,
            balancer,
            forward_addr,
            #[cfg(target_os = "macos")]
            launchd_socket_name: None,
        }
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_socket_name(&mut self, n: String) {
        self.launchd_socket_name = Some(n);
    }

    pub async fn build(self) -> io::Result<TunnelTcpServer> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                let listener = match self.launchd_socket_name {
                    Some(launchd_socket_name) => {
                        use tokio::net::TcpListener as TokioTcpListener;
                        use crate::net::launch_activate_socket::get_launch_activate_tcp_listener;

                        let std_listener = get_launch_activate_tcp_listener(&launchd_socket_name, true)?;
                        let tokio_listener = TokioTcpListener::from_std(std_listener)?;
                        ShadowTcpListener::from_listener(tokio_listener, self.context.accept_opts())?
                    } _ => {
                        create_standard_tcp_listener(&self.context, &self.client_config).await?
                    }
                };
            } else {
                let listener = create_standard_tcp_listener(&self.context, &self.client_config).await?;
            }
        }

        Ok(TunnelTcpServer {
            context: self.context,
            listener,
            balancer: self.balancer,
            forward_addr: self.forward_addr,
        })
    }
}

/// TCP Tunnel instance
pub struct TunnelTcpServer {
    context: Arc<ServiceContext>,
    listener: ShadowTcpListener,
    balancer: PingBalancer,
    forward_addr: Option<Address>,
}

impl TunnelTcpServer {
    /// Server's local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        if let Some(ref addr) = self.forward_addr {
            info!("shadowsocks TCP tunnel listening on {}, forward to {}", self.listener.local_addr()?, addr);
        } else {
            info!("shadowsocks TCP tunnel listening on {}, dynamic forward", self.listener.local_addr()?);
        }

        let forward_addr = self.forward_addr.map(Arc::new);
        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            tokio::spawn(handle_tcp_client(
                self.context.clone(),
                stream,
                self.balancer.clone(),
                peer_addr,
                forward_addr.clone(),
            ));
        }
    }
}

async fn handle_tcp_client(
    context: Arc<ServiceContext>,
    mut stream: TcpStream,
    balancer: PingBalancer,
    peer_addr: SocketAddr,
    forward_addr: Option<Arc<Address>>,
) -> io::Result<()> {
    // Static mode: use pre-configured forward_addr.
    // Dynamic mode: read ATYP+ADDR+PORT from the client stream.
    let owned_addr: Address;
    let target_addr: &Address = match forward_addr {
        Some(ref a) => a,
        None => {
            owned_addr = match Address::read_from(&mut stream).await {
                Ok(addr) => addr,
                Err(err) => {
                    error!("received invalid TCP tunnel connection from {}: {}", peer_addr, err);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("read target address: {}", err)));
                }
            };
            trace!("dynamic tunnel {} -> {}", peer_addr, owned_addr);
            &owned_addr
        }
    };

    if balancer.is_empty() {
        trace!("establishing tcp tunnel {} <-> {} direct", peer_addr, target_addr);

        let mut remote = AutoProxyClientStream::connect_bypassed(context, target_addr).await?;
        return establish_tcp_tunnel_bypassed(&mut stream, &mut remote, peer_addr, target_addr).await;
    }

    let server = balancer.best_tcp_server();
    let svr_cfg = server.server_config();
    trace!(
        "establishing tcp tunnel {} <-> {} through server {} (outbound: {})",
        peer_addr,
        target_addr,
        svr_cfg.tcp_external_addr(),
        svr_cfg.addr(),
    );

    let mut remote =
        AutoProxyClientStream::connect_proxied_with_opts(context, &server, target_addr, server.connect_opts_ref())
            .await?;
    establish_tcp_tunnel(svr_cfg, &mut stream, &mut remote, peer_addr, target_addr).await
}
