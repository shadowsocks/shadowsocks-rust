//! UDP Tunnel server

use std::{
    io::{self, Cursor},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{BufMut, Bytes, BytesMut};
use futures::future::{self, AbortHandle};
use io::ErrorKind;
use log::{debug, error, info, trace, warn};
use lru_time_cache::{Entry, LruCache};
use shadowsocks::{
    lookup_then,
    net::UdpSocket as ShadowUdpSocket,
    relay::{
        socks5::{Address, UdpAssociateHeader},
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
    ServerConfig,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    config::ClientConfig,
    local::{
        context::ServiceContext,
        loadbalancing::{
            BasicServerIdent,
            PingBalancer,
            PingBalancerBuilder,
            ServerIdent,
            ServerType as BalancerServerType,
        },
    },
    net::MonProxySocket,
};

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
struct Socks5Bound {
    src: SocketAddr,
    dst: Address,
}

pub struct Socks5UdpServer {
    context: Arc<ServiceContext>,
    assoc_map: Arc<Mutex<LruCache<Socks5Bound, UdpAssociation>>>,
}

impl Socks5UdpServer {
    pub fn new(context: Arc<ServiceContext>, time_to_live: Duration, capacity: usize) -> Socks5UdpServer {
        Socks5UdpServer {
            context,
            assoc_map: Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(
                time_to_live,
                capacity,
            ))),
        }
    }

    pub async fn run(&mut self, client_config: &ClientConfig, servers: Vec<ServerConfig>) -> io::Result<()> {
        let socket = match *client_config {
            ClientConfig::SocketAddr(ref saddr) => UdpSocket::bind(saddr).await?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(&self.context.context_ref(), dname, port, |addr| {
                    UdpSocket::bind(addr).await
                })?
                .1
            }
        };

        info!(
            "shadowsocks socks5 UDP listening on {}",
            socket.local_addr().expect("listener.local_addr"),
        );

        let mut balancer_builder = PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Udp);

        for server in servers {
            let server_ident = BasicServerIdent::new(server);
            balancer_builder.add_server(server_ident);
        }

        let (balancer, checker) = balancer_builder.build();
        tokio::spawn(checker);

        let listener = Arc::new(socket);

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, peer_addr) = match listener.recv_from(&mut buffer).await {
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

            let bound = Socks5Bound {
                src: peer_addr,
                dst: header.address,
            };

            if let Err(err) = self.send_packet(&listener, bound.clone(), &balancer, payload).await {
                error!(
                    "udp packet relay {} -> {} with {} bytes failed, error: {}",
                    bound.src,
                    bound.dst,
                    data.len(),
                    err
                );
            }
        }
    }

    async fn send_packet(
        &mut self,
        listener: &Arc<UdpSocket>,
        assoc_key: Socks5Bound,
        balancer: &PingBalancer<BasicServerIdent>,
        data: &[u8],
    ) -> io::Result<()> {
        let mut assoc_map = self.assoc_map.lock().await;
        let assoc = match assoc_map.entry(assoc_key.clone()) {
            Entry::Occupied(occ) => occ.into_mut(),
            Entry::Vacant(vac) => {
                let target_addr = &assoc_key.dst;

                // Pending packets 64 should be good enough for a server.
                // If there are plenty of packets stuck in the channel, dropping exccess packets is a good way to protect the server from
                // being OOM.
                let (sender, receiver) = mpsc::channel(64);

                let r2l_abortable = if self.context.check_target_bypassed(target_addr).await {
                    let socket = ShadowUdpSocket::connect_remote_with_opts(
                        self.context.context_ref(),
                        target_addr,
                        self.context.connect_opts_ref(),
                    )
                    .await?;
                    let socket: Arc<UdpSocket> = Arc::new(socket.into());

                    let (r2l_fut, r2l_abortable) = future::abortable(UdpAssociation::copy_bypassed_r2l(
                        listener.clone(),
                        assoc_key.clone(),
                        socket.clone(),
                        self.assoc_map.clone(),
                    ));

                    // CLIENT <- REMOTE
                    tokio::spawn(r2l_fut);

                    // CLIENT -> REMOTE
                    let l2r_fut = UdpAssociation::copy_bypassed_l2r(socket, assoc_key.clone(), receiver);
                    tokio::spawn(l2r_fut);

                    debug!(
                        "established udp tunnel {} <-> {} (bypassed) with {:?}",
                        assoc_key.src,
                        assoc_key.dst,
                        self.context.connect_opts_ref()
                    );

                    r2l_abortable
                } else {
                    let server = balancer.best_server();
                    let svr_cfg = server.server_config();

                    let socket = ProxySocket::connect_with_opts(
                        self.context.context(),
                        svr_cfg,
                        self.context.connect_opts_ref(),
                    )
                    .await?;
                    let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
                    let socket = Arc::new(socket);

                    let (r2l_fut, r2l_abortable) = future::abortable(UdpAssociation::copy_proxied_r2l(
                        listener.clone(),
                        assoc_key.clone(),
                        socket.clone(),
                        self.assoc_map.clone(),
                    ));

                    // CLIENT <- REMOTE
                    tokio::spawn(r2l_fut);

                    // CLIENT -> REMOTE
                    let l2r_fut = UdpAssociation::copy_proxied_l2r(socket, assoc_key.clone(), receiver);
                    tokio::spawn(l2r_fut);

                    debug!(
                        "established udp tunnel {} <-> {} (proxied) with {:?}",
                        assoc_key.src,
                        assoc_key.dst,
                        self.context.connect_opts_ref()
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
        assoc_key: Socks5Bound,
        mut receiver: mpsc::Receiver<Bytes>,
    ) {
        while let Some(data) = receiver.recv().await {
            if let Err(err) = outbound.send(&assoc_key.dst, &data).await {
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
        inbound: Arc<UdpSocket>,
        assoc_key: Socks5Bound,
        outbound: Arc<MonProxySocket>,
        assoc_map: Arc<Mutex<LruCache<Socks5Bound, UdpAssociation>>>,
    ) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut payload_buffer = BytesMut::new();
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
            payload_buffer.clear();

            // Resssemble packet
            let header = UdpAssociateHeader::new(0, assoc_key.dst.clone());
            payload_buffer.reserve(header.serialized_len() + n);

            header.write_to_buf(&mut payload_buffer);
            payload_buffer.put_slice(data);

            // Send back to client
            if let Err(err) = inbound.send_to(&payload_buffer, assoc_key.src).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    assoc_key.src, assoc_key.dst, err
                );
            }

            trace!(
                "udp relay {} <- {} with {} bytes",
                assoc_key.src,
                assoc_key.dst,
                payload_buffer.len()
            );
        }
    }

    async fn copy_bypassed_l2r(outbound: Arc<UdpSocket>, assoc_key: Socks5Bound, mut receiver: mpsc::Receiver<Bytes>) {
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
        inbound: Arc<UdpSocket>,
        assoc_key: Socks5Bound,
        outbound: Arc<UdpSocket>,
        assoc_map: Arc<Mutex<LruCache<Socks5Bound, UdpAssociation>>>,
    ) -> io::Result<()> {
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
