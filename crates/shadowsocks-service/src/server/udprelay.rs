//! Shadowsocks UDP server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use io::ErrorKind;
use log::{debug, error, info, trace, warn};
use lru_time_cache::LruCache;
use shadowsocks::{
    lookup_then,
    net::{AcceptOpts, UdpSocket as OutboundUdpSocket},
    relay::{
        socks5::Address,
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
    ServerConfig,
};
use spin::Mutex as SpinMutex;
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
    time,
};

use crate::net::MonProxySocket;

use super::context::ServiceContext;

type AssociationMap = LruCache<SocketAddr, UdpAssociation>;
type SharedAssociationMap = Arc<Mutex<AssociationMap>>;

pub struct UdpServer {
    context: Arc<ServiceContext>,
    assoc_map: SharedAssociationMap,
    cleanup_abortable: JoinHandle<()>,
    keepalive_abortable: JoinHandle<()>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    accept_opts: AcceptOpts,
}

impl Drop for UdpServer {
    fn drop(&mut self) {
        self.cleanup_abortable.abort();
        self.keepalive_abortable.abort();
    }
}

impl UdpServer {
    pub fn new(
        context: Arc<ServiceContext>,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        accept_opts: AcceptOpts,
    ) -> UdpServer {
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

        UdpServer {
            context,
            assoc_map,
            cleanup_abortable,
            keepalive_abortable,
            keepalive_tx,
            accept_opts,
        }
    }

    pub async fn run(mut self, svr_cfg: &ServerConfig) -> io::Result<()> {
        let socket = ProxySocket::bind_with_opts(self.context.context(), svr_cfg, self.accept_opts.clone()).await?;

        info!(
            "shadowsocks udp server listening on {}",
            socket.local_addr().expect("listener.local_addr"),
        );

        let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
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

            if self.context.check_outbound_blocked(&target_addr).await {
                error!("udp client {} outbound {} blocked by ACL rules", peer_addr, target_addr);
                continue;
            }

            let data = &buffer[..n];
            if let Err(err) = self.send_packet(&listener, peer_addr, target_addr, data).await {
                error!(
                    "udp packet relay {} with {} bytes failed, error: {}",
                    peer_addr,
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
        target_addr: Address,
        data: &[u8],
    ) -> io::Result<()> {
        let mut assoc_map = self.assoc_map.lock().await;

        if let Some(assoc) = assoc_map.get(&peer_addr) {
            return assoc.try_send((target_addr, Bytes::copy_from_slice(data)));
        }

        let assoc = UdpAssociation::new(
            self.context.clone(),
            listener.clone(),
            peer_addr,
            self.keepalive_tx.clone(),
        );

        trace!("created udp association for {}", peer_addr);

        assoc.try_send((target_addr, Bytes::copy_from_slice(data)))?;
        assoc_map.insert(peer_addr, assoc);

        Ok(())
    }
}

struct UdpAssociation {
    assoc: Arc<UdpAssociationContext>,
    sender: mpsc::Sender<(Address, Bytes)>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.assoc.outbound_ipv4_socket.lock().abort();
        self.assoc.outbound_ipv6_socket.lock().abort();
    }
}

impl UdpAssociation {
    fn new(
        context: Arc<ServiceContext>,
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
    ) -> UdpAssociation {
        let (assoc, sender) = UdpAssociationContext::new(context, inbound, peer_addr, keepalive_tx);
        UdpAssociation { assoc, sender }
    }

    fn try_send(&self, data: (Address, Bytes)) -> io::Result<()> {
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
        socket: Arc<OutboundUdpSocket>,
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

    fn set_connected(&mut self, socket: Arc<OutboundUdpSocket>, abortable: JoinHandle<io::Result<()>>) {
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
    inbound: Arc<MonProxySocket>,
    peer_addr: SocketAddr,
    outbound_ipv4_socket: SpinMutex<UdpAssociationState>,
    outbound_ipv6_socket: SpinMutex<UdpAssociationState>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
}

impl Drop for UdpAssociationContext {
    fn drop(&mut self) {
        trace!("udp association for {} is closed", self.peer_addr);
    }
}

impl UdpAssociationContext {
    fn new(
        context: Arc<ServiceContext>,
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
    ) -> (Arc<UdpAssociationContext>, mpsc::Sender<(Address, Bytes)>) {
        // Pending packets 1024 should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(1024);

        let assoc = Arc::new(UdpAssociationContext {
            context,
            inbound,
            peer_addr,
            outbound_ipv4_socket: SpinMutex::new(UdpAssociationState::empty()),
            outbound_ipv6_socket: SpinMutex::new(UdpAssociationState::empty()),
            keepalive_tx,
        });

        let l2r_task = {
            let assoc = assoc.clone();
            assoc.copy_l2r(receiver)
        };
        tokio::spawn(l2r_task);

        (assoc, sender)
    }

    async fn copy_l2r(self: Arc<Self>, mut receiver: mpsc::Receiver<(Address, Bytes)>) {
        while let Some((target_addr, data)) = receiver.recv().await {
            trace!(
                "udp relay {} -> {} with {} bytes",
                self.peer_addr,
                target_addr,
                data.len()
            );

            let assoc = self.clone();
            if let Err(err) = assoc.copy_l2r_dispatch(&target_addr, &data).await {
                error!(
                    "udp relay {} -> {} with {} bytes, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );
            }
        }
    }

    async fn copy_l2r_dispatch(self: Arc<Self>, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        match *target_addr {
            Address::SocketAddress(sa) => match sa {
                SocketAddr::V4(..) => self.copy_ipv4_l2r_dispatch(sa, data).await,
                SocketAddr::V6(..) => self.copy_ipv6_l2r_dispatch(sa, data).await,
            },
            Address::DomainNameAddress(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |sa| {
                    match sa {
                        SocketAddr::V4(..) => self.clone().copy_ipv4_l2r_dispatch(sa, data).await,
                        SocketAddr::V6(..) => self.clone().copy_ipv6_l2r_dispatch(sa, data).await,
                    }
                })?;

                Ok(())
            }
        }
    }

    async fn copy_ipv4_l2r_dispatch(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let outbound = {
            let mut handle = self.outbound_ipv4_socket.lock();

            match *handle {
                UdpAssociationState::Empty => {
                    // Create a new connection to proxy server

                    let socket =
                        OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    let socket: Arc<OutboundUdpSocket> = Arc::new(socket);

                    // CLIENT <- REMOTE
                    let r2l_abortable = {
                        let assoc = self.clone();
                        tokio::spawn(assoc.copy_r2l(socket.clone()))
                    };
                    debug!(
                        "created udp association for {} with {:?}",
                        self.peer_addr,
                        self.context.connect_opts_ref()
                    );

                    handle.set_connected(socket.clone(), r2l_abortable);
                    socket
                }
                UdpAssociationState::Connected { ref socket, .. } => socket.clone(),
                UdpAssociationState::Aborted => {
                    debug!(
                        "udp association for {} (bypassed) have been aborted, dropped packet {} bytes to {}",
                        self.peer_addr,
                        data.len(),
                        target_addr
                    );
                    return Ok(());
                }
            }
        };

        let n = outbound.send_to(data, target_addr).await?;
        if n != data.len() {
            warn!(
                "{} -> {} sent {} bytes != expected {} bytes",
                self.peer_addr,
                target_addr,
                n,
                data.len()
            );
        }

        Ok(())
    }

    async fn copy_ipv6_l2r_dispatch(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let outbound = {
            let mut handle = self.outbound_ipv6_socket.lock();

            match *handle {
                UdpAssociationState::Empty => {
                    // Create a new connection to proxy server

                    let socket =
                        OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    let socket: Arc<OutboundUdpSocket> = Arc::new(socket);

                    // CLIENT <- REMOTE
                    let r2l_abortable = {
                        let assoc = self.clone();
                        tokio::spawn(assoc.copy_r2l(socket.clone()))
                    };
                    debug!(
                        "created udp association for {} with {:?}",
                        self.peer_addr,
                        self.context.connect_opts_ref()
                    );

                    handle.set_connected(socket.clone(), r2l_abortable);
                    socket
                }
                UdpAssociationState::Connected { ref socket, .. } => socket.clone(),
                UdpAssociationState::Aborted => {
                    debug!(
                        "udp association for {} (bypassed) have been aborted, dropped packet {} bytes to {}",
                        self.peer_addr,
                        data.len(),
                        target_addr
                    );
                    return Ok(());
                }
            }
        };

        let n = outbound.send_to(data, target_addr).await?;
        if n != data.len() {
            warn!(
                "{} -> {} sent {} bytes != expected {} bytes",
                self.peer_addr,
                target_addr,
                n,
                data.len()
            );
        }

        Ok(())
    }

    async fn copy_r2l(self: Arc<Self>, outbound: Arc<OutboundUdpSocket>) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, addr) = match outbound.recv_from(&mut buffer).await {
                Ok(r) => {
                    // Keep association alive in map
                    let _ = self
                        .keepalive_tx
                        .send_timeout(self.peer_addr, Duration::from_secs(1))
                        .await;
                    r
                }
                Err(err) => {
                    error!(
                        "udp failed to receive from outbound socket, peer_addr: {}, error: {}",
                        self.peer_addr, err
                    );
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            trace!("udp relay {} <- {} received {} bytes", self.peer_addr, addr, n);

            let data = &buffer[..n];

            let target_addr = Address::from(addr);

            // Send back to client
            if let Err(err) = self.inbound.send_to(self.peer_addr, &target_addr, data).await {
                warn!(
                    "udp failed to send back to client {}, from target {} ({}), error: {}",
                    self.peer_addr, target_addr, addr, err
                );
            }

            trace!(
                "udp relay {} <- {} ({}) with {} bytes",
                self.peer_addr,
                target_addr,
                addr,
                data.len()
            );
        }
    }
}
