//! UDP Tunnel server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::future::{self, AbortHandle};
use io::ErrorKind;
use log::{debug, error, info, trace, warn};
use lru_time_cache::{Entry, LruCache};
use shadowsocks::{
    lookup_then,
    net::UdpSocket as ShadowUdpSocket,
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
    config::ClientConfig,
    local::{context::ServiceContext, loadbalancing::PingBalancer},
    net::MonProxySocket,
};

pub struct UdpTunnel {
    context: Arc<ServiceContext>,
    assoc_map: Arc<Mutex<LruCache<SocketAddr, UdpAssociation>>>,
    cleanup_abortable: AbortHandle,
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        self.cleanup_abortable.abort();
    }
}

impl UdpTunnel {
    pub fn new(context: Arc<ServiceContext>, time_to_live: Option<Duration>, capacity: Option<usize>) -> UdpTunnel {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = Arc::new(Mutex::new(match capacity {
            Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            None => LruCache::with_expiry_duration(time_to_live),
        }));

        let cleanup_abortable = {
            let assoc_map = assoc_map.clone();
            let (cleanup_task, cleanup_abortable) = future::abortable(async move {
                let mut interval = time::interval(time_to_live);
                loop {
                    interval.tick().await;

                    // iter() will trigger a cleanup of expired associations
                    let _ = assoc_map.lock().await.iter();
                }
            });
            tokio::spawn(cleanup_task);
            cleanup_abortable
        };

        UdpTunnel {
            context,
            assoc_map,
            cleanup_abortable,
        }
    }

    pub async fn run(
        &mut self,
        client_config: &ClientConfig,
        balancer: PingBalancer,
        forward_addr: &Address,
    ) -> io::Result<()> {
        let socket = match *client_config {
            ClientConfig::SocketAddr(ref saddr) => ShadowUdpSocket::bind(&saddr).await?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(&self.context.context_ref(), dname, port, |addr| {
                    ShadowUdpSocket::bind(&addr).await
                })?
                .1
            }
        };
        let socket: UdpSocket = socket.into();

        info!("shadowsocks UDP tunnel listening on {}", socket.local_addr()?);

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
            if let Err(err) = self
                .send_packet(&listener, peer_addr, &balancer, &forward_addr, data)
                .await
            {
                error!(
                    "udp packet relay {} -> {} with {} bytes failed, error: {}",
                    peer_addr,
                    forward_addr,
                    data.len(),
                    err
                );
            }
        }
    }

    async fn send_packet(
        &mut self,
        listener: &Arc<UdpSocket>,
        peer_addr: SocketAddr,
        balancer: &PingBalancer,
        forward_addr: &Address,
        data: &[u8],
    ) -> io::Result<()> {
        let mut assoc_map = self.assoc_map.lock().await;
        let assoc = match assoc_map.entry(peer_addr) {
            Entry::Occupied(occ) => occ.into_mut(),
            Entry::Vacant(vac) => {
                let server = balancer.best_udp_server();
                let svr_cfg = server.server_config();

                let socket =
                    ProxySocket::connect_with_opts(self.context.context(), svr_cfg, self.context.connect_opts_ref())
                        .await?;
                let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
                let socket = Arc::new(socket);

                // Pending packets 64 should be good enough for a server.
                // If there are plenty of packets stuck in the channel, dropping exccess packets is a good way to protect the server from
                // being OOM.
                let (sender, receiver) = mpsc::channel(64);

                let (r2l_fut, r2l_abortable) = future::abortable(UdpAssociation::copy_r2l(
                    listener.clone(),
                    peer_addr,
                    socket.clone(),
                    forward_addr.clone(),
                    self.assoc_map.clone(),
                ));

                // CLIENT <- REMOTE
                tokio::spawn(r2l_fut);

                // CLIENT -> REMOTE
                let l2r_fut = UdpAssociation::copy_l2r(socket, peer_addr, forward_addr.clone(), receiver);
                tokio::spawn(l2r_fut);

                debug!(
                    "established udp tunnel {} <-> {} with {:?}",
                    peer_addr,
                    forward_addr,
                    self.context.connect_opts_ref()
                );

                vac.insert(UdpAssociation {
                    sender,
                    peer_addr,
                    r2l_abortable,
                })
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
    peer_addr: SocketAddr,
    r2l_abortable: AbortHandle,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.r2l_abortable.abort();
        trace!("udp tunnel for {} is closed", self.peer_addr);
    }
}

impl UdpAssociation {
    async fn copy_l2r(
        outbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        target_addr: Address,
        mut receiver: mpsc::Receiver<Bytes>,
    ) {
        while let Some(data) = receiver.recv().await {
            if let Err(err) = outbound.send(&target_addr, &data).await {
                error!("udp failed to send to {} outbound socket, error: {}", target_addr, err);
            } else {
                trace!("udp relay {} -> {} with {} bytes", peer_addr, target_addr, data.len());
            }
        }
    }

    async fn copy_r2l(
        inbound: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        outbound: Arc<MonProxySocket>,
        target_addr: Address,
        assoc_map: Arc<Mutex<LruCache<SocketAddr, UdpAssociation>>>,
    ) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, _) = match outbound.recv(&mut buffer).await {
                Ok(n) => {
                    // Keep association alive in map
                    let _ = assoc_map.lock().await.get(&peer_addr);
                    n
                }
                Err(err) => {
                    error!(
                        "udp failed to receive from {} outbound socket, error: {}",
                        target_addr, err
                    );
                    time::sleep(Duration::from_secs(0)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // Send back to client
            if let Err(err) = inbound.send_to(data, peer_addr).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    peer_addr, target_addr, err
                );
            }

            trace!("udp relay {} <- {} with {} bytes", peer_addr, target_addr, data.len());
        }
    }
}
