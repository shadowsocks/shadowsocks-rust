//! Shadowsocks UDP server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::future::{self, AbortHandle};
use io::ErrorKind;
use log::{debug, error, info, trace, warn};
use lru_time_cache::{Entry, LruCache};
use shadowsocks::{
    context::SharedContext,
    net::{ConnectOpts, UdpSocket as OutboundUdpSocket},
    relay::{
        socks5::Address,
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
    ServerConfig,
};
use tokio::{sync::mpsc, time};

use crate::{
    local::acl::AccessControl,
    net::{FlowStat, MonProxySocket},
};

pub struct UdpServer {
    context: SharedContext,
    flow_stat: Arc<FlowStat>,
    connect_opts: ConnectOpts,
    assoc_map: LruCache<String, UdpAssociation>,
    acl: Option<Arc<AccessControl>>,
}

impl UdpServer {
    pub fn new(
        context: SharedContext,
        flow_stat: Arc<FlowStat>,
        connect_opts: ConnectOpts,
        time_to_live: Duration,
        capacity: usize,
        acl: Option<Arc<AccessControl>>,
    ) -> UdpServer {
        UdpServer {
            context,
            flow_stat,
            connect_opts,
            assoc_map: LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            acl,
        }
    }

    pub async fn run(mut self, svr_cfg: &ServerConfig) -> io::Result<()> {
        let socket = ProxySocket::bind(self.context.clone(), svr_cfg).await?;

        info!(
            "shadowsocks udp server listening on {}",
            socket.local_addr().expect("listener.local_addr"),
        );

        let socket = MonProxySocket::from_socket(socket, self.flow_stat.clone());
        let listener = Arc::new(socket);

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, peer_addr, target_addr) = match listener.recv_from(&mut buffer).await {
                Ok(s) => s,
                Err(err) => {
                    error!("udp server recv_from failed with error: {}", err);
                    continue;
                }
            };

            if let Some(ref acl) = self.acl {
                if acl.check_outbound_blocked(&self.context, &target_addr).await {
                    error!("udp client {} outbound {} blocked by ACL rules", peer_addr, target_addr);
                    continue;
                }
            }

            let data = &buffer[..n];
            if let Err(err) = self.send_packet(&listener, peer_addr, &target_addr, data).await {
                error!(
                    "udp packet relay {} -> {} with {} bytes failed, error: {}",
                    peer_addr,
                    target_addr,
                    data.len(),
                    err
                );
            }
        }
    }

    async fn send_packet(
        &mut self,
        listener: &Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        target_addr: &Address,
        data: &[u8],
    ) -> io::Result<()> {
        let cache_key = format!("{}+{}", peer_addr, target_addr);

        let assoc = match self.assoc_map.entry(cache_key) {
            Entry::Occupied(occ) => occ.into_mut(),
            Entry::Vacant(vac) => {
                let socket =
                    OutboundUdpSocket::connect_remote_with_opts(&self.context, target_addr, &self.connect_opts).await?;
                let socket = Arc::new(socket);

                // Pending packets 64 should be good enough for a server.
                // If there are plenty of packets stuck in the channel, dropping exccess packets is a good way to protect the server from
                // being OOM.
                let (sender, receiver) = mpsc::channel(64);

                let (r2l_fut, r2l_abortable) = future::abortable(UdpAssociation::copy_r2l(
                    listener.clone(),
                    peer_addr,
                    socket.clone(),
                    target_addr.clone(),
                ));

                // CLIENT <- REMOTE
                tokio::spawn(r2l_fut);

                // CLIENT -> REMOTE
                let l2r_fut = UdpAssociation::copy_l2r(socket, peer_addr, target_addr.clone(), receiver);
                tokio::spawn(l2r_fut);

                debug!(
                    "established udp tunnel {} <-> {} with {:?}",
                    peer_addr, target_addr, self.connect_opts
                );

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
    async fn copy_l2r(
        outbound: Arc<OutboundUdpSocket>,
        peer_addr: SocketAddr,
        target_addr: Address,
        mut receiver: mpsc::Receiver<Bytes>,
    ) {
        while let Some(data) = receiver.recv().await {
            if let Err(err) = outbound.send(&data).await {
                error!("udp failed to send to {} outbound socket, error: {}", target_addr, err);
            } else {
                trace!("udp relay {} -> {} with {} bytes", peer_addr, target_addr, data.len());
            }
        }
    }

    async fn copy_r2l(
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        outbound: Arc<OutboundUdpSocket>,
        target_addr: Address,
    ) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let n = match outbound.recv(&mut buffer).await {
                Ok(n) => n,
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
            if let Err(err) = inbound.send_to(peer_addr, &target_addr, data).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    peer_addr, target_addr, err
                );
            }

            trace!("udp relay {} <- {} with {} bytes", peer_addr, target_addr, data.len());
        }
    }
}
