//! UDP Tunnel server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use log::{debug, error, info};
use shadowsocks::{
    lookup_then,
    net::UdpSocket as ShadowUdpSocket,
    relay::{socks5::Address, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
    ServerAddr,
};
use tokio::{net::UdpSocket, time};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::{UdpAssociationManager, UdpInboundWrite},
};

#[derive(Clone)]
struct TunnelUdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

#[async_trait]
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
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        client_config: &ServerAddr,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        balancer: PingBalancer,
        forward_addr: Address,
    ) -> io::Result<TunnelUdpServer> {
        let socket = match client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                ShadowUdpSocket::listen_with_opts(saddr, context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, *port, |addr| {
                    ShadowUdpSocket::listen_with_opts(&addr, context.accept_opts()).await
                })?
                .1
            }
        };
        let socket: UdpSocket = socket.into();
        let listener = Arc::new(socket);

        Ok(TunnelUdpServer {
            context,
            time_to_live,
            capacity,
            listener,
            balancer,
            forward_addr,
        })
    }

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
