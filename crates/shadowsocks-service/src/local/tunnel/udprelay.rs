//! UDP Tunnel server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::future::{self, AbortHandle};
use io::ErrorKind;
use log::{debug, error, info, trace, warn};
use lru_time_cache::{Entry, LruCache};
use shadowsocks::{
    lookup_then,
    relay::{
        socks5::Address,
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
    ServerConfig,
};
use tokio::{net::UdpSocket, sync::mpsc, time};

use crate::{
    config::ClientConfig,
    local::{
        context::ServiceContext,
        loadbalancing::{BasicServerIdent, PingBalancerBuilder, ServerIdent, ServerType as BalancerServerType},
    },
    net::MonProxySocket,
};

pub struct UdpTunnel {
    context: Arc<ServiceContext>,
    assoc_map: LruCache<String, UdpAssociation>,
}

impl UdpTunnel {
    pub fn new(context: Arc<ServiceContext>, time_to_live: Duration, capacity: usize) -> UdpTunnel {
        UdpTunnel {
            context,
            assoc_map: LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
        }
    }

    pub async fn run(
        &mut self,
        client_config: &ClientConfig,
        servers: Vec<ServerConfig>,
        forward_addr: &Address,
    ) -> io::Result<()> {
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
            "shadowsocks udp server listening on {}",
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

            let server = balancer.best_server();

            let data = &buffer[..n];
            if let Err(err) = self
                .send_packet(&listener, peer_addr, server, &forward_addr, data)
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
        server: Arc<BasicServerIdent>,
        forward_addr: &Address,
        data: &[u8],
    ) -> io::Result<()> {
        let svr_cfg = server.server_config();
        let cache_key = format!("{}+{}", peer_addr, svr_cfg.addr());

        let assoc = match self.assoc_map.entry(cache_key) {
            Entry::Occupied(occ) => occ.into_mut(),
            Entry::Vacant(vac) => {
                let socket =
                    ProxySocket::connect_with_opts(self.context.context(), svr_cfg, self.context.connect_opts())
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
                    self.context.connect_opts()
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
    ) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, _) = match outbound.recv(&mut buffer).await {
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
