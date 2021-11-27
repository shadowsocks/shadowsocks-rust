//! UDP Tunnel server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use io::ErrorKind;
use log::{debug, error, info, trace, warn};
use lru_time_cache::LruCache;
use shadowsocks::{
    lookup_then,
    net::UdpSocket as ShadowUdpSocket,
    relay::{
        socks5::Address,
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
    ServerAddr,
};
use spin::Mutex as SpinMutex;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    task::JoinHandle,
    time,
};

use crate::{
    local::{context::ServiceContext, loadbalancing::PingBalancer},
    net::MonProxySocket,
};

type AssociationMap = LruCache<SocketAddr, UdpAssociation>;
type SharedAssociationMap = Arc<Mutex<AssociationMap>>;

pub struct UdpTunnel {
    context: Arc<ServiceContext>,
    assoc_map: SharedAssociationMap,
    cleanup_abortable: JoinHandle<()>,
    keepalive_abortable: JoinHandle<()>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        self.cleanup_abortable.abort();
        self.keepalive_abortable.abort();
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
            tokio::spawn(async move {
                loop {
                    time::sleep(time_to_live).await;

                    // cleanup expired associations. iter() will remove expired elements
                    let _ = assoc_map.lock().await.iter();
                }
            })
        };

        let (keepalive_tx, mut keepalive_rx) = mpsc::channel(64);

        let keepalive_abortable = {
            let assoc_map = assoc_map.clone();
            tokio::spawn(async move {
                while let Some(peer_addr) = keepalive_rx.recv().await {
                    assoc_map.lock().await.get(&peer_addr);
                }
            })
        };

        UdpTunnel {
            context,
            assoc_map,
            cleanup_abortable,
            keepalive_abortable,
            keepalive_tx,
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
                .send_packet(&listener, peer_addr, &balancer, forward_addr, data)
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

        if let Some(assoc) = assoc_map.get(&peer_addr) {
            return assoc.try_send(Bytes::copy_from_slice(data));
        }

        let assoc = UdpAssociation::new(
            self.context.clone(),
            listener.clone(),
            peer_addr,
            forward_addr.clone(),
            self.keepalive_tx.clone(),
            balancer.clone(),
        );

        trace!("created udp association for {}", peer_addr);

        assoc.try_send(Bytes::copy_from_slice(data))?;
        assoc_map.insert(peer_addr, assoc);

        Ok(())
    }
}

struct UdpAssociation {
    sender: mpsc::Sender<Bytes>,
    assoc: Arc<UdpAssociationContext>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.assoc.proxied_socket.lock().abort();
    }
}

impl UdpAssociation {
    fn new(
        context: Arc<ServiceContext>,
        inbound: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        forward_addr: Address,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer,
    ) -> UdpAssociation {
        let (assoc, sender) =
            UdpAssociationContext::new(context, inbound, peer_addr, forward_addr, keepalive_tx, balancer);
        UdpAssociation { sender, assoc }
    }

    fn try_send(&self, data: Bytes) -> io::Result<()> {
        if let Err(..) = self.sender.try_send(data) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err);
        }
        Ok(())
    }
}

enum UdpAssociationState {
    Empty,
    Connected {
        socket: Arc<MonProxySocket>,
        abortable: JoinHandle<io::Result<()>>,
    },
    Aborted,
}

impl Drop for UdpAssociationState {
    fn drop(&mut self) {
        self.abort_inner();
    }
}

impl UdpAssociationState {
    fn empty() -> UdpAssociationState {
        UdpAssociationState::Empty
    }

    fn reset(&mut self) {
        self.abort_inner();
        *self = UdpAssociationState::Empty;
    }

    fn set_connected(&mut self, socket: Arc<MonProxySocket>, abortable: JoinHandle<io::Result<()>>) {
        self.abort_inner();
        *self = UdpAssociationState::Connected { socket, abortable };
    }

    fn abort(&mut self) {
        self.abort_inner();
        *self = UdpAssociationState::Aborted;
    }

    fn abort_inner(&mut self) {
        if let UdpAssociationState::Connected { ref abortable, .. } = *self {
            abortable.abort();
        }
    }
}

struct UdpAssociationContext {
    context: Arc<ServiceContext>,
    inbound: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    forward_addr: Address,
    proxied_socket: SpinMutex<UdpAssociationState>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    balancer: PingBalancer,
}

impl Drop for UdpAssociationContext {
    fn drop(&mut self) {
        trace!("udp tunnel for {} is closed", self.peer_addr);
    }
}

impl UdpAssociationContext {
    fn new(
        context: Arc<ServiceContext>,
        inbound: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        forward_addr: Address,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer,
    ) -> (Arc<UdpAssociationContext>, mpsc::Sender<Bytes>) {
        // Pending packets 1024 should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(1024);

        let assoc = Arc::new(UdpAssociationContext {
            context,
            inbound,
            peer_addr,
            forward_addr,
            proxied_socket: SpinMutex::new(UdpAssociationState::empty()),
            keepalive_tx,
            balancer,
        });

        let l2r_task = {
            let assoc = assoc.clone();
            assoc.copy_l2r(receiver)
        };
        tokio::spawn(l2r_task);

        (assoc, sender)
    }

    async fn copy_l2r(self: Arc<Self>, mut receiver: mpsc::Receiver<Bytes>) {
        while let Some(data) = receiver.recv().await {
            if let Err(err) = self.clone().copy_proxied_l2r(&data).await {
                error!(
                    "udp failed to send to {} outbound socket, error: {}",
                    self.forward_addr, err
                );
            } else {
                trace!(
                    "udp relay {} -> {} with {} bytes",
                    self.peer_addr,
                    self.forward_addr,
                    data.len()
                );
            }
        }
    }

    async fn copy_proxied_l2r(self: Arc<Self>, data: &[u8]) -> io::Result<()> {
        let mut last_err = io::Error::new(ErrorKind::Other, "udp relay sendto failed after retry");
        let target_addr = &self.forward_addr;

        for tried in 0..3 {
            let socket = {
                let mut handle = self.proxied_socket.lock();

                match *handle {
                    UdpAssociationState::Empty => {
                        // Create a new connection to proxy server

                        let server = self.balancer.best_udp_server();
                        let svr_cfg = server.server_config();

                        let socket = ProxySocket::connect_with_opts(
                            self.context.context(),
                            svr_cfg,
                            self.context.connect_opts_ref(),
                        )
                        .await?;
                        let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
                        let socket = Arc::new(socket);

                        // CLIENT <- REMOTE
                        let r2l_abortable = {
                            let assoc = self.clone();
                            tokio::spawn(assoc.copy_proxied_r2l(socket.clone()))
                        };

                        debug!(
                            "created udp association for {} <-> {} (proxied) with {:?}",
                            self.peer_addr,
                            svr_cfg.addr(),
                            self.context.connect_opts_ref()
                        );

                        handle.set_connected(socket.clone(), r2l_abortable);
                        socket
                    }
                    UdpAssociationState::Connected { ref socket, .. } => socket.clone(),
                    UdpAssociationState::Aborted => {
                        debug!(
                            "udp association for {} (proxied) have been aborted, dropped packet {} bytes to {}",
                            self.peer_addr,
                            data.len(),
                            target_addr
                        );
                        return Ok(());
                    }
                }
            };

            match socket.send(target_addr, data).await {
                Ok(..) => return Ok(()),
                Err(err) => {
                    debug!(
                        "{} -> {} (proxied) sending {} bytes failed, tried: {}, error: {}",
                        self.peer_addr,
                        target_addr,
                        data.len(),
                        tried + 1,
                        err
                    );
                    last_err = err;

                    // Reset for reconnecting
                    self.proxied_socket.lock().reset();

                    tokio::task::yield_now().await;
                }
            }
        }

        Err(last_err)
    }

    async fn copy_proxied_r2l(self: Arc<Self>, outbound: Arc<MonProxySocket>) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let n = match outbound.recv(&mut buffer).await {
                Ok((n, addr)) => {
                    trace!("udp relay {} <- {} received {} bytes", self.peer_addr, addr, n);
                    // Keep association alive in map
                    let _ = self
                        .keepalive_tx
                        .send_timeout(self.peer_addr, Duration::from_secs(1))
                        .await;
                    n
                }
                Err(err) => {
                    // Socket that connected to remote server returns an error, it should be ECONNREFUSED in most cases.
                    // That indicates that the association on the server side have been dropped.
                    //
                    // There is no point to keep this socket. Drop it immediately.
                    self.proxied_socket.lock().reset();

                    error!(
                        "udp failed to receive from {} outbound socket, error: {}",
                        self.forward_addr, err
                    );
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // Send back to client
            if let Err(err) = self.inbound.send_to(data, self.peer_addr).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    self.peer_addr, self.forward_addr, err
                );
            }

            trace!(
                "udp relay {} <- {} with {} bytes",
                self.peer_addr,
                self.forward_addr,
                data.len()
            );
        }
    }
}
