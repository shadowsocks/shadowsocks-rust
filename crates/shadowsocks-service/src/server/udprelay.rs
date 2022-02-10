//! Shadowsocks UDP server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::future;
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

            if self.context.check_client_blocked(&peer_addr) {
                warn!(
                    "udp client {} outbound {} access denied by ACL rules",
                    peer_addr, target_addr
                );
                continue;
            }

            if self.context.check_outbound_blocked(&target_addr).await {
                warn!("udp client {} outbound {} blocked by ACL rules", peer_addr, target_addr);
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

        debug!("created udp association for {}", peer_addr);

        assoc.try_send((target_addr, Bytes::copy_from_slice(data)))?;
        assoc_map.insert(peer_addr, assoc);

        Ok(())
    }
}

struct UdpAssociation {
    assoc_handle: JoinHandle<()>,
    sender: mpsc::Sender<(Address, Bytes)>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.assoc_handle.abort();
    }
}

impl UdpAssociation {
    fn new(
        context: Arc<ServiceContext>,
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
    ) -> UdpAssociation {
        let (assoc_handle, sender) = UdpAssociationContext::create(context, inbound, peer_addr, keepalive_tx);
        UdpAssociation { assoc_handle, sender }
    }

    fn try_send(&self, data: (Address, Bytes)) -> io::Result<()> {
        if let Err(..) = self.sender.try_send(data) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err);
        }
        Ok(())
    }
}

struct UdpAssociationContext {
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    outbound_ipv4_socket: Option<OutboundUdpSocket>,
    outbound_ipv6_socket: Option<OutboundUdpSocket>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    inbound: Arc<MonProxySocket>,
}

impl Drop for UdpAssociationContext {
    fn drop(&mut self) {
        debug!("udp association for {} is closed", self.peer_addr);
    }
}

impl UdpAssociationContext {
    fn create(
        context: Arc<ServiceContext>,
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
    ) -> (JoinHandle<()>, mpsc::Sender<(Address, Bytes)>) {
        // Pending packets 128 for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(128);

        let mut assoc = UdpAssociationContext {
            context,
            peer_addr,
            outbound_ipv4_socket: None,
            outbound_ipv6_socket: None,
            keepalive_tx,
            inbound,
        };
        let handle = tokio::spawn(async move { assoc.dispatch_packet(receiver).await });

        (handle, sender)
    }

    async fn dispatch_packet(&mut self, mut receiver: mpsc::Receiver<(Address, Bytes)>) {
        let mut outbound_ipv4_buffer = Vec::new();
        let mut outbound_ipv6_buffer = Vec::new();

        loop {
            tokio::select! {
                packet_received_opt = receiver.recv() => {
                    let (target_addr, data) = match packet_received_opt {
                        Some(d) => d,
                        None => {
                            trace!("udp association for {} -> ... channel closed", self.peer_addr);
                            break;
                        }
                    };

                    self.dispatch_received_packet(&target_addr, &data).await;
                }

                received_opt = receive_from_outbound_opt(&self.outbound_ipv4_socket, &mut outbound_ipv4_buffer) => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.outbound_ipv4_socket = None;
                            continue;
                        }
                    };

                    let addr = Address::from(addr);
                    self.send_received_respond_packet(&addr, &outbound_ipv4_buffer[..n]).await;
                }

                received_opt = receive_from_outbound_opt(&self.outbound_ipv6_socket, &mut outbound_ipv6_buffer) => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.outbound_ipv6_socket = None;
                            continue;
                        }
                    };

                    let addr = Address::from(addr);
                    self.send_received_respond_packet(&addr, &outbound_ipv6_buffer[..n]).await;
                }
            }
        }

        #[inline]
        async fn receive_from_outbound_opt(
            socket: &Option<OutboundUdpSocket>,
            buf: &mut Vec<u8>,
        ) -> io::Result<(usize, SocketAddr)> {
            match *socket {
                None => future::pending().await,
                Some(ref s) => {
                    if buf.is_empty() {
                        buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                    }
                    s.recv_from(buf).await
                }
            }
        }
    }

    async fn dispatch_received_packet(&mut self, target_addr: &Address, data: &[u8]) {
        trace!(
            "udp relay {} -> {} with {} bytes",
            self.peer_addr,
            target_addr,
            data.len()
        );

        if self.context.check_outbound_blocked(target_addr).await {
            error!(
                "udp client {} outbound {} blocked by ACL rules",
                self.peer_addr, target_addr
            );
            return;
        }

        if let Err(err) = self.dispatch_received_outbound_packet(target_addr, data).await {
            error!(
                "udp relay {} -> {} with {} bytes, error: {}",
                self.peer_addr,
                target_addr,
                data.len(),
                err
            );
        }
    }

    async fn dispatch_received_outbound_packet(&mut self, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        match *target_addr {
            Address::SocketAddress(sa) => self.send_received_outbound_packet(sa, data).await,
            Address::DomainNameAddress(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |sa| {
                    self.send_received_outbound_packet(sa, data).await
                })
                .map(|_| ())
            }
        }
    }

    async fn send_received_outbound_packet(&mut self, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let socket = match target_addr {
            SocketAddr::V4(..) => match self.outbound_ipv4_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    self.outbound_ipv4_socket.insert(socket)
                }
            },
            SocketAddr::V6(..) => match self.outbound_ipv6_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    self.outbound_ipv6_socket.insert(socket)
                }
            },
        };

        let n = socket.send_to(data, target_addr).await?;
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

    async fn send_received_respond_packet(&mut self, addr: &Address, data: &[u8]) {
        trace!("udp relay {} <- {} received {} bytes", self.peer_addr, addr, data.len());

        // Keep association alive in map
        let _ = self
            .keepalive_tx
            .send_timeout(self.peer_addr, Duration::from_secs(1))
            .await;

        // Send back to client
        if let Err(err) = self.inbound.send_to(self.peer_addr, addr, data).await {
            warn!(
                "udp failed to send back to client {}, from target {}, error: {}",
                self.peer_addr, addr, err
            );
        } else {
            trace!("udp relay {} <- {} with {} bytes", self.peer_addr, addr, data.len());
        }
    }
}
