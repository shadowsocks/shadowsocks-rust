//! UDP Tunnel server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use log::{debug, error, info};
use shadowsocks::{
    ServerAddr,
    relay::{socks5::Address, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
};
use tokio::{net::UdpSocket, time};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::{UdpAssociationManager, UdpInboundWrite, udp::listener::create_standard_udp_listener},
};

pub struct TunnelUdpServerBuilder {
    context: Arc<ServiceContext>,
    client_config: ServerAddr,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
    balancer: PingBalancer,
    forward_addr: Address,
    #[cfg(target_os = "macos")]
    launchd_socket_name: Option<String>,
}

impl TunnelUdpServerBuilder {
    pub(crate) fn new(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        balancer: PingBalancer,
        forward_addr: Address,
    ) -> Self {
        Self {
            context,
            client_config,
            time_to_live,
            capacity,
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

    pub async fn build(self) -> io::Result<TunnelUdpServer> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                let socket = match self.launchd_socket_name {
                    Some(launchd_socket_name) => {
                        use tokio::net::UdpSocket as TokioUdpSocket;
                        use crate::net::launch_activate_socket::get_launch_activate_udp_socket;

                        let std_socket = get_launch_activate_udp_socket(&launchd_socket_name, true)?;
                        TokioUdpSocket::from_std(std_socket)?
                    } _ => {
                        create_standard_udp_listener(&self.context, &self.client_config).await?.into()
                    }
                };
            } else {
                let socket = create_standard_udp_listener(&self.context, &self.client_config).await?.into();
            }
        }

        Ok(TunnelUdpServer {
            context: self.context,
            time_to_live: self.time_to_live,
            capacity: self.capacity,
            listener: Arc::new(socket),
            balancer: self.balancer,
            forward_addr: self.forward_addr,
        })
    }
}

#[derive(Clone)]
struct TunnelUdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

impl UdpInboundWrite for TunnelUdpInboundWriter {
    async fn send_to(&self, peer_addr: SocketAddr, _remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        self.inbound.send_to(data, peer_addr).await.map(|_| ())
    }
}

pub struct TunnelUdpServer {
    context: Arc<ServiceContext>,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
    listener: Arc<UdpSocket>,
    balancer: PingBalancer,
    forward_addr: Address,
}

impl TunnelUdpServer {
    /// Get server's local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        info!("shadowsocks UDP tunnel listening on {}", self.listener.local_addr()?);

        let (mut manager, cleanup_interval, mut keepalive_rx) = UdpAssociationManager::new(
            self.context.clone(),
            TunnelUdpInboundWriter {
                inbound: self.listener.clone(),
            },
            self.time_to_live,
            self.capacity,
            self.balancer,
        );

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut cleanup_timer = time::interval(cleanup_interval);

        loop {
            tokio::select! {
                _ = cleanup_timer.tick() => {
                    // cleanup expired associations. iter() will remove expired elements
                    manager.cleanup_expired().await;
                }

                peer_addr_opt = keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                    manager.keep_alive(&peer_addr).await;
                }

                recv_result = self.listener.recv_from(&mut buffer) => {
                    let (n, peer_addr) = match recv_result {
                        Ok(s) => s,
                        Err(err) => {
                            error!("udp server recv_from failed with error: {}", err);
                            time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };

                    if n == 0 {
                        // For windows, it will generate a ICMP Port Unreachable Message
                        // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
                        // Which will result in recv_from return 0.
                        //
                        // It cannot be solved here, because `WSAGetLastError` is already set.
                        //
                        // See `relay::udprelay::utils::create_socket` for more detail.
                        continue;
                    }

                    let data = &buffer[..n];
                    if let Err(err) = manager.send_to(peer_addr, self.forward_addr.clone(), data)
                        .await
                    {
                        debug!(
                            "udp packet relay {} -> {} with {} bytes failed, error: {}",
                            peer_addr,
                            self.forward_addr,
                            data.len(),
                            err
                        );
                    }
                }
            }
        }
    }
}
