//! UDP Tunnel server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::BytesMut;
use log::{debug, error, info, trace};
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
    forward_addr: Option<Address>,
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
        forward_addr: Option<Address>,
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

/// Static tunnel mode: forward_addr is fixed, responses go directly to client.
#[derive(Clone)]
struct StaticTunnelUdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

impl UdpInboundWrite for StaticTunnelUdpInboundWriter {
    async fn send_to(&self, peer_addr: SocketAddr, _remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        self.inbound.send_to(data, peer_addr).await.map(|_| ())
    }
}

/// Dynamic tunnel mode: forward_addr is per-packet, responses are prefixed with ATYP+ADDR+PORT.
#[derive(Clone)]
struct DynamicTunnelUdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

impl UdpInboundWrite for DynamicTunnelUdpInboundWriter {
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        // Prepend ATYP+ADDR+PORT header so the client can identify which target sent this response
        let addr_len = remote_addr.serialized_len();
        let mut buf = BytesMut::with_capacity(addr_len + data.len());
        remote_addr.write_to_buf(&mut buf);
        buf.extend_from_slice(data);
        self.inbound.send_to(&buf, peer_addr).await.map(|_| ())
    }
}

pub struct TunnelUdpServer {
    context: Arc<ServiceContext>,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
    listener: Arc<UdpSocket>,
    balancer: PingBalancer,
    forward_addr: Option<Address>,
}

impl TunnelUdpServer {
    /// Get server's local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(mut self) -> io::Result<()> {
        match self.forward_addr.take() {
            Some(addr) => self.run_static(addr).await,
            None => self.run_dynamic().await,
        }
    }

    /// Static mode: all packets forwarded to a fixed address (original behavior)
    async fn run_static(self, forward_addr: Address) -> io::Result<()> {
        info!(
            "shadowsocks UDP tunnel listening on {}, forward to {}",
            self.listener.local_addr()?,
            forward_addr
        );

        let (mut manager, cleanup_interval, mut keepalive_rx) = UdpAssociationManager::new(
            self.context.clone(),
            StaticTunnelUdpInboundWriter {
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
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectedly");
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
                    if let Err(err) = manager.send_to(peer_addr, forward_addr.clone(), data).await {
                        debug!(
                            "udp packet relay {} -> {} with {} bytes failed, error: {}",
                            peer_addr, forward_addr, data.len(), err
                        );
                    }
                }
            }
        }
    }

    /// Dynamic mode: parse ATYP+ADDR+PORT from each packet, prepend header to responses
    async fn run_dynamic(self) -> io::Result<()> {
        info!(
            "shadowsocks UDP tunnel listening on {}, dynamic forward",
            self.listener.local_addr()?
        );

        let (mut manager, cleanup_interval, mut keepalive_rx) = UdpAssociationManager::new(
            self.context.clone(),
            DynamicTunnelUdpInboundWriter {
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
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectedly");
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

                    // Parse ATYP+ADDR+PORT from packet prefix
                    let mut cursor = io::Cursor::new(&buffer[..n]);
                    let target_addr = match Address::read_cursor(&mut cursor) {
                        Ok(addr) => addr,
                        Err(err) => {
                            error!(
                                "received invalid UDP tunnel packet from {}: {}",
                                peer_addr, err
                            );
                            continue;
                        }
                    };

                    let header_len = cursor.position() as usize;
                    let payload = &buffer[header_len..n];

                    trace!("dynamic tunnel {} -> {}", peer_addr, target_addr);

                    if let Err(err) = manager.send_to(peer_addr, target_addr.clone(), payload).await {
                        debug!(
                            "udp packet relay {} -> {} with {} bytes failed, error: {}",
                            peer_addr, target_addr, payload.len(), err
                        );
                    }
                }
            }
        }
    }
}
