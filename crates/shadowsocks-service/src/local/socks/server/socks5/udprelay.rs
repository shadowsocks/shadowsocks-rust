//! UDP Tunnel server

use std::{
    io::{self, Cursor},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use log::{debug, error, info, trace};
use shadowsocks::{
    lookup_then,
    net::UdpSocket as ShadowUdpSocket,
    relay::{
        socks5::{Address, UdpAssociateHeader},
        udprelay::MAXIMUM_UDP_PAYLOAD_SIZE,
    },
    ServerAddr,
};
use tokio::{net::UdpSocket, time};

use crate::{
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UdpAssociationManager, UdpInboundWrite},
    },
    net::utils::to_ipv4_mapped,
};

#[derive(Clone)]
struct Socks5UdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

#[async_trait]
impl UdpInboundWrite for Socks5UdpInboundWriter {
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        let remote_addr = match remote_addr {
            Address::SocketAddress(sa) => {
                // Try to convert IPv4 mapped IPv6 address if server is running on dual-stack mode
                let saddr = match *sa {
                    SocketAddr::V4(..) => *sa,
                    SocketAddr::V6(ref v6) => match to_ipv4_mapped(v6.ip()) {
                        Some(v4) => SocketAddr::new(IpAddr::from(v4), v6.port()),
                        None => *sa,
                    },
                };

                Address::SocketAddress(saddr)
            }
            daddr => daddr.clone(),
        };

        // Reassemble packet
        let mut payload_buffer = BytesMut::new();
        let header = UdpAssociateHeader::new(0, remote_addr.clone());
        payload_buffer.reserve(header.serialized_len() + data.len());

        header.write_to_buf(&mut payload_buffer);
        payload_buffer.put_slice(data);

        self.inbound.send_to(&payload_buffer, peer_addr).await.map(|_| ())
    }
}

/// SOCKS5 UDP server instance
pub struct Socks5UdpServer {
    context: Arc<ServiceContext>,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
    listener: Arc<UdpSocket>,
    balancer: PingBalancer,
}

impl Socks5UdpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        client_config: &ServerAddr,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        balancer: PingBalancer,
    ) -> io::Result<Socks5UdpServer> {
        let socket = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                ShadowUdpSocket::listen_with_opts(saddr, context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, port, |addr| {
                    ShadowUdpSocket::listen_with_opts(&addr, context.accept_opts()).await
                })?
                .1
            }
        };
        let socket: UdpSocket = socket.into();
        let listener = Arc::new(socket);

        Ok(Socks5UdpServer {
            context,
            time_to_live,
            capacity,
            listener,
            balancer,
        })
    }

    /// Server's listen address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run server accept loop
    pub async fn run(self) -> io::Result<()> {
        info!("shadowsocks socks5 UDP listening on {}", self.listener.local_addr()?);

        let (mut manager, cleanup_interval, mut keepalive_rx) = UdpAssociationManager::new(
            self.context.clone(),
            Socks5UdpInboundWriter {
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

                    let data = &buffer[..n];

                    // PKT = UdpAssociateHeader + PAYLOAD
                    let mut cur = Cursor::new(data);
                    let header = match UdpAssociateHeader::read_from(&mut cur).await {
                        Ok(h) => h,
                        Err(..) => {
                            error!("received invalid UDP associate packet: {:?}", ByteStr::new(data));
                            continue;
                        }
                    };

                    if header.frag != 0 {
                        error!("received UDP associate with frag != 0, which is not supported by shadowsocks");
                        continue;
                    }

                    let pos = cur.position() as usize;
                    let payload = &data[pos..];

                    trace!(
                        "UDP ASSOCIATE {} -> {}, {} bytes",
                        peer_addr,
                        header.address,
                        payload.len()
                    );

                    if let Err(err) = manager.send_to(peer_addr, header.address, payload).await {
                        debug!(
                            "udp packet from {} relay {} bytes failed, error: {}",
                            peer_addr,
                            data.len(),
                            err
                        );
                    }
                }
            }
        }
    }
}
