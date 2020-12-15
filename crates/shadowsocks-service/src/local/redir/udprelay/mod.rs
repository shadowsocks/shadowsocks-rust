//! UDP transparent proxy

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures::future::{self, AbortHandle};
use log::{debug, error, info, trace, warn};
use lru_time_cache::{Entry, LruCache};
use shadowsocks::{
    config::ServerConfig,
    lookup_then,
    relay::{
        socks5::Address,
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    config::{ClientConfig, RedirType},
    local::{
        context::ServiceContext,
        loadbalancing::{
            BasicServerIdent,
            PingBalancer,
            PingBalancerBuilder,
            ServerIdent,
            ServerType as BalancerServerType,
        },
        redir::redir_ext::UdpSocketRedirExt,
    },
    net::MonProxySocket,
};

use self::sys::UdpRedirSocket;

mod sys;

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
struct RedirBound {
    src: SocketAddr,
    dst: SocketAddr,
}

pub struct UdpRedir {
    context: Arc<ServiceContext>,
    redir_ty: RedirType,
    assoc_map: Arc<Mutex<LruCache<RedirBound, UdpAssociation>>>,
}

impl UdpRedir {
    pub fn new(context: Arc<ServiceContext>, redir_ty: RedirType, time_to_live: Duration, capacity: usize) -> UdpRedir {
        UdpRedir {
            context,
            redir_ty,
            assoc_map: Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(
                time_to_live,
                capacity,
            ))),
        }
    }

    pub async fn run(&mut self, client_config: &ClientConfig, servers: Vec<ServerConfig>) -> io::Result<()> {
        let listener = match *client_config {
            ClientConfig::SocketAddr(ref saddr) => UdpRedirSocket::bind(self.redir_ty, *saddr)?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |addr| {
                    UdpRedirSocket::bind(self.redir_ty, addr)
                })?
                .1
            }
        };

        let local_addr = listener.local_addr().expect("determine port bound to");
        info!("shadowsocks UDP redirect listening on {}", local_addr);

        let mut balancer_builder = PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Udp);

        for server in servers {
            let server_ident = BasicServerIdent::new(server);
            balancer_builder.add_server(server_ident);
        }

        let (balancer, checker) = balancer_builder.build();
        tokio::spawn(checker);

        let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (recv_len, src, dst) = match listener.recv_from_redir(&mut pkt_buf).await {
                Ok(o) => o,
                Err(err) => {
                    error!("recv_from_redir failed with err: {}", err);
                    continue;
                }
            };

            // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
            // Copy bytes, because udp_associate runs in another tokio Task
            let pkt = &pkt_buf[..recv_len];

            trace!(
                "received UDP packet from {}, destination {}, length {} bytes",
                src,
                dst,
                recv_len
            );

            if recv_len == 0 {
                // For windows, it will generate a ICMP Port Unreachable Message
                // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
                // Which will result in recv_from return 0.
                //
                // It cannot be solved here, because `WSAGetLastError` is already set.
                //
                // See `relay::udprelay::utils::create_socket` for more detail.
                continue;
            }

            // Check destination should be proxied or not
            let target = Address::SocketAddress(dst);
            let is_bypassed = self.context.check_target_bypassed(&target).await;

            // Check or (re)create an association
            let assoc_key = RedirBound { src, dst };

            if let Err(err) = self.send_packet(assoc_key, &balancer, pkt).await {
                error!(
                    "udp packet relay {} -> {} with {} bytes failed, error: {}",
                    assoc_key.src,
                    assoc_key.dst,
                    pkt.len(),
                    err
                );
            }
        }
    }

    async fn send_packet(
        &mut self,
        assoc_key: RedirBound,
        balancer: &PingBalancer<BasicServerIdent>,
        data: &[u8],
    ) -> io::Result<()> {
        let mut assoc_map = self.assoc_map.lock().await;
        let assoc = match assoc_map.entry(assoc_key) {
            Entry::Occupied(occ) => occ.into_mut(),
            Entry::Vacant(vac) => {
                let target_addr = Address::from(assoc_key.src);

                // Pending packets 64 should be good enough for a server.
                // If there are plenty of packets stuck in the channel, dropping exccess packets is a good way to protect the server from
                // being OOM.
                let (sender, receiver) = mpsc::channel(64);

                let r2l_abortable = if self.context.check_target_bypassed(&target_addr).await {
                    let socket = match assoc_key.dst {
                        SocketAddr::V4(..) => UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?,
                        SocketAddr::V6(..) => UdpSocket::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)).await?,
                    };
                    socket.connect(assoc_key.dst).await?;
                    let socket = Arc::new(socket);

                    let (r2l_fut, r2l_abortable) = future::abortable(UdpAssociation::copy_bypassed_r2l(
                        self.redir_ty,
                        assoc_key,
                        socket.clone(),
                        self.assoc_map.clone(),
                    ));

                    // CLIENT <- REMOTE
                    tokio::spawn(r2l_fut);

                    // CLIENT -> REMOTE
                    let l2r_fut = UdpAssociation::copy_bypassed_l2r(socket, assoc_key, receiver);
                    tokio::spawn(l2r_fut);

                    debug!(
                        "established udp tunnel {} <-> {} (bypassed) with {:?}",
                        assoc_key.src,
                        assoc_key.dst,
                        self.context.connect_opts()
                    );

                    r2l_abortable
                } else {
                    let server = balancer.best_server();
                    let svr_cfg = server.server_config();

                    let socket =
                        ProxySocket::connect_with_opts(self.context.context(), svr_cfg, self.context.connect_opts())
                            .await?;
                    let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
                    let socket = Arc::new(socket);

                    let (r2l_fut, r2l_abortable) = future::abortable(UdpAssociation::copy_proxied_r2l(
                        self.redir_ty,
                        assoc_key,
                        socket.clone(),
                        self.assoc_map.clone(),
                    ));

                    // CLIENT <- REMOTE
                    tokio::spawn(r2l_fut);

                    // CLIENT -> REMOTE
                    let l2r_fut = UdpAssociation::copy_proxied_l2r(socket, assoc_key, receiver);
                    tokio::spawn(l2r_fut);

                    debug!(
                        "established udp tunnel {} <-> {} (proxied) with {:?}",
                        assoc_key.src,
                        assoc_key.dst,
                        self.context.connect_opts()
                    );

                    r2l_abortable
                };

                vac.insert(UdpAssociation { sender, r2l_abortable })
            }
        };

        if let Err(..) = assoc.sender.try_send(Bytes::copy_from_slice(data)) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err);
        }

        Ok(())
    }
}

struct UdpAssociation {
    sender: mpsc::Sender<Bytes>,
    r2l_abortable: AbortHandle,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.r2l_abortable.abort();
    }
}

impl UdpAssociation {
    async fn copy_proxied_l2r(
        outbound: Arc<MonProxySocket>,
        assoc_key: RedirBound,
        mut receiver: mpsc::Receiver<Bytes>,
    ) {
        let target_addr = Address::from(assoc_key.dst);

        while let Some(data) = receiver.recv().await {
            if let Err(err) = outbound.send(&target_addr, &data).await {
                error!(
                    "udp failed to send to {} outbound socket, error: {}",
                    assoc_key.dst, err
                );
            } else {
                trace!(
                    "udp relay {} -> {} with {} bytes",
                    assoc_key.src,
                    assoc_key.dst,
                    data.len()
                );
            }
        }
    }

    async fn copy_proxied_r2l(
        redir_ty: RedirType,
        assoc_key: RedirBound,
        outbound: Arc<MonProxySocket>,
        assoc_map: Arc<Mutex<LruCache<RedirBound, UdpAssociation>>>,
    ) -> io::Result<()> {
        // Create a socket binds to destination addr
        // This only works for systems that supports binding to non-local addresses
        let inbound = UdpRedirSocket::bind(redir_ty, assoc_key.dst)?;

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, _) = match outbound.recv(&mut buffer).await {
                Ok(n) => {
                    // Keep association alive in map
                    let _ = assoc_map.lock().await.get(&assoc_key);
                    n
                }
                Err(err) => {
                    error!(
                        "udp failed to receive from {} outbound socket, error: {}",
                        assoc_key.dst, err
                    );
                    time::sleep(Duration::from_secs(0)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // Send back to client
            if let Err(err) = inbound.send_to(data, assoc_key.src).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    assoc_key.src, assoc_key.dst, err
                );
            }

            trace!(
                "udp relay {} <- {} with {} bytes",
                assoc_key.src,
                assoc_key.dst,
                data.len()
            );
        }
    }

    async fn copy_bypassed_l2r(outbound: Arc<UdpSocket>, assoc_key: RedirBound, mut receiver: mpsc::Receiver<Bytes>) {
        while let Some(data) = receiver.recv().await {
            if let Err(err) = outbound.send(&data).await {
                error!(
                    "udp failed to send to {} outbound socket, error: {}",
                    assoc_key.dst, err
                );
            } else {
                trace!(
                    "udp relay {} -> {} with {} bytes",
                    assoc_key.src,
                    assoc_key.dst,
                    data.len()
                );
            }
        }
    }

    async fn copy_bypassed_r2l(
        redir_ty: RedirType,
        assoc_key: RedirBound,
        outbound: Arc<UdpSocket>,
        assoc_map: Arc<Mutex<LruCache<RedirBound, UdpAssociation>>>,
    ) -> io::Result<()> {
        // Create a socket binds to destination addr
        // This only works for systems that supports binding to non-local addresses
        let inbound = UdpRedirSocket::bind(redir_ty, assoc_key.dst)?;

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let n = match outbound.recv(&mut buffer).await {
                Ok(n) => {
                    // Keep association alive in map
                    let _ = assoc_map.lock().await.get(&assoc_key);
                    n
                }
                Err(err) => {
                    error!(
                        "udp failed to receive from {} outbound socket, error: {}",
                        assoc_key.dst, err
                    );
                    time::sleep(Duration::from_secs(0)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // Send back to client
            if let Err(err) = inbound.send_to(data, assoc_key.src).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    assoc_key.src, assoc_key.dst, err
                );
            }

            trace!(
                "udp relay {} <- {} with {} bytes",
                assoc_key.src,
                assoc_key.dst,
                data.len()
            );
        }
    }
}
