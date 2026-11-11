//! UDP Tunnel server

use std::{
    collections::HashMap,
    io::{self, Cursor},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use futures::future;
use log::{debug, error, info, trace};
use shadowsocks::{
    ServerAddr,
    relay::{
        socks5::{Address, UdpAssociateHeader},
        udprelay::MAXIMUM_UDP_PAYLOAD_SIZE,
    },
};
use tokio::{net::UdpSocket, sync::mpsc, time};

use crate::{
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UdpAssociationManager, UdpInboundWrite, udp::listener::create_standard_udp_listener},
    },
    net::utils::to_ipv4_mapped,
};

/// Client endpoints holding a live, authenticated UDP ASSOCIATE control connection (RFC 1928 section 7)
///
/// Key is (client IP, client UDP port), port 0 means any port of that IP.
#[derive(Clone)]
pub struct Socks5UdpClients {
    clients: Arc<Mutex<HashMap<(IpAddr, u16), usize>>>,
    closed_tx: mpsc::UnboundedSender<()>,
}

impl Socks5UdpClients {
    /// Allows UDP from `ip:port` (any port if 0) until the returned guard is dropped
    pub fn register(&self, ip: IpAddr, port: u16) -> Socks5UdpClientGuard {
        let key = (ip.to_canonical(), port);
        *self.clients.lock().unwrap().entry(key).or_insert(0) += 1;
        Socks5UdpClientGuard {
            clients: self.clone(),
            key,
        }
    }

    pub fn is_allowed(&self, peer_addr: &SocketAddr) -> bool {
        let ip = peer_addr.ip().to_canonical();
        let clients = self.clients.lock().unwrap();
        clients.contains_key(&(ip, 0)) || clients.contains_key(&(ip, peer_addr.port()))
    }
}

pub struct Socks5UdpClientGuard {
    clients: Socks5UdpClients,
    key: (IpAddr, u16),
}

impl Drop for Socks5UdpClientGuard {
    fn drop(&mut self) {
        let mut clients = self.clients.clients.lock().unwrap();
        if let Some(count) = clients.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                clients.remove(&self.key);
            }
        }
        let _ = self.clients.closed_tx.send(());
    }
}

/// Only peers in `clients` may use the relay; associations are dropped once their control connection closes
pub struct Socks5UdpAuth {
    pub clients: Socks5UdpClients,
    closed_rx: mpsc::UnboundedReceiver<()>,
}

impl Socks5UdpAuth {
    pub fn new() -> Self {
        let (closed_tx, closed_rx) = mpsc::unbounded_channel();
        let clients = Socks5UdpClients {
            clients: Arc::new(Mutex::new(HashMap::new())),
            closed_tx,
        };
        Self { clients, closed_rx }
    }
}

pub struct Socks5UdpServerBuilder {
    context: Arc<ServiceContext>,
    client_config: ServerAddr,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
    balancer: PingBalancer,
    auth: Option<Socks5UdpAuth>,
    #[cfg(target_os = "macos")]
    launchd_socket_name: Option<String>,
}

impl Socks5UdpServerBuilder {
    pub(crate) fn new(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        balancer: PingBalancer,
        auth: Option<Socks5UdpAuth>,
    ) -> Self {
        Self {
            context,
            client_config,
            time_to_live,
            capacity,
            balancer,
            auth,
            #[cfg(target_os = "macos")]
            launchd_socket_name: None,
        }
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_socket_name(&mut self, n: String) {
        self.launchd_socket_name = Some(n);
    }

    pub async fn build(self) -> io::Result<Socks5UdpServer> {
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

        Ok(Socks5UdpServer {
            context: self.context,
            time_to_live: self.time_to_live,
            capacity: self.capacity,
            listener: Arc::new(socket),
            balancer: self.balancer,
            auth: self.auth,
        })
    }
}

#[derive(Clone)]
struct Socks5UdpInboundWriter {
    inbound: Arc<UdpSocket>,
}

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
    auth: Option<Socks5UdpAuth>,
}

impl Socks5UdpServer {
    /// Server's listen address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run server accept loop
    pub async fn run(self) -> io::Result<()> {
        info!("shadowsocks socks5 UDP listening on {}", self.listener.local_addr()?);

        let (clients, mut closed_rx) = match self.auth {
            Some(auth) => (Some(auth.clients), Some(auth.closed_rx)),
            None => (None, None),
        };

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
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectedly");
                    manager.keep_alive(&peer_addr).await;
                }

                _ = async {
                    match closed_rx {
                        Some(ref mut rx) => rx.recv().await,
                        None => future::pending().await,
                    }
                } => {
                    // A control connection was closed, drop the associations it was authorizing
                    if let Some(ref clients) = clients {
                        manager.retain(|peer_addr| clients.is_allowed(peer_addr));
                    }
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

                    if let Some(ref clients) = clients
                        && !clients.is_allowed(&peer_addr)
                    {
                        debug!("dropped UDP packet from {} without an authenticated UDP ASSOCIATE", peer_addr);
                        continue;
                    }

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
