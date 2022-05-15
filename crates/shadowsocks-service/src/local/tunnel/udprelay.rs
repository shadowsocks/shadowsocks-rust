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

pub struct UdpTunnel {
    context: Arc<ServiceContext>,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
}

impl UdpTunnel {
    pub fn new(context: Arc<ServiceContext>, time_to_live: Option<Duration>, capacity: Option<usize>) -> UdpTunnel {
        UdpTunnel {
            context,
            time_to_live,
            capacity,
        }
    }

    pub async fn run(
        &mut self,
        client_config: &ServerAddr,
        balancer: PingBalancer,
        forward_addr: &Address,
    ) -> io::Result<()> {
        let socket = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                ShadowUdpSocket::listen_with_opts(saddr, self.context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |addr| {
                    ShadowUdpSocket::listen_with_opts(&addr, self.context.accept_opts()).await
                })?
                .1
            }
        };
        let socket: UdpSocket = socket.into();

        info!("shadowsocks UDP tunnel listening on {}", socket.local_addr()?);

        let listener = Arc::new(socket);
        let (mut manager, cleanup_interval, mut keepalive_rx) = UdpAssociationManager::new(
            self.context.clone(),
            TunnelUdpInboundWriter {
                inbound: listener.clone(),
            },
            self.time_to_live,
            self.capacity,
            balancer,
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

                recv_result = listener.recv_from(&mut buffer) => {
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
                    if let Err(err) = manager.send_to(peer_addr, forward_addr.clone(), data)
                        .await
                    {
                        debug!(
                            "udp packet relay {} -> {} with {} bytes failed, error: {}",
                            peer_addr,
                            forward_addr,
                            data.len(),
                            err
                        );
                    }
                }
            }
        }
    }
}
