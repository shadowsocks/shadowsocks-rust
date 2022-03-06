//! UDP Association Managing

use std::{
    io::{self, ErrorKind},
    marker::PhantomData,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use futures::future;
use log::{debug, error, trace, warn};
use lru_time_cache::LruCache;
use tokio::{sync::mpsc, task::JoinHandle, time};

use shadowsocks::{
    lookup_then,
    net::UdpSocket as ShadowUdpSocket,
    relay::{
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
        Address,
    },
};

use crate::{
    local::{context::ServiceContext, loadbalancing::PingBalancer},
    net::{MonProxySocket, UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE, UDP_ASSOCIATION_SEND_CHANNEL_SIZE},
};

/// Writer for sending packets back to client
///
/// Currently it requires `async-trait` for `async fn` in trait, which will allocate a `Box`ed `Future` every call of `send_to`.
/// This performance issue could be solved when `generic_associated_types` and `generic_associated_types` are stabilized.
#[async_trait]
pub trait UdpInboundWrite {
    /// Sends packet `data` received from `remote_addr` back to `peer_addr`
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()>;
}

type AssociationMap<W> = LruCache<SocketAddr, UdpAssociation<W>>;

/// UDP association manager
pub struct UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    respond_writer: W,
    context: Arc<ServiceContext>,
    assoc_map: AssociationMap<W>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    balancer: PingBalancer,
}

impl<W> UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    /// Create a new `UdpAssociationManager`
    ///
    /// Returns (`UdpAssociationManager`, Cleanup Interval, Keep-alive Receiver<SocketAddr>)
    pub fn new(
        context: Arc<ServiceContext>,
        respond_writer: W,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        balancer: PingBalancer,
    ) -> (UdpAssociationManager<W>, Duration, mpsc::Receiver<SocketAddr>) {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = match capacity {
            Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            None => LruCache::with_expiry_duration(time_to_live),
        };

        let (keepalive_tx, keepalive_rx) = mpsc::channel(UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE);

        (
            UdpAssociationManager {
                respond_writer,
                context,
                assoc_map,
                keepalive_tx,
                balancer,
            },
            time_to_live,
            keepalive_rx,
        )
    }

    /// Sends `data` from `peer_addr` to `target_addr`
    pub async fn send_to(&mut self, peer_addr: SocketAddr, target_addr: Address, data: &[u8]) -> io::Result<()> {
        // Check or (re)create an association

        if let Some(assoc) = self.assoc_map.get(&peer_addr) {
            return assoc.try_send((target_addr, Bytes::copy_from_slice(data)));
        }

        let assoc = UdpAssociation::new(
            self.context.clone(),
            peer_addr,
            self.keepalive_tx.clone(),
            self.balancer.clone(),
            self.respond_writer.clone(),
        );

        debug!("created udp association for {}", peer_addr);

        assoc.try_send((target_addr, Bytes::copy_from_slice(data)))?;
        self.assoc_map.insert(peer_addr, assoc);

        Ok(())
    }

    /// Cleanup expired associations
    pub async fn cleanup_expired(&mut self) {
        self.assoc_map.iter();
    }

    /// Keep-alive association
    pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
        self.assoc_map.get(peer_addr);
    }
}

struct UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    assoc_handle: JoinHandle<()>,
    sender: mpsc::Sender<(Address, Bytes)>,
    writer: PhantomData<W>,
}

impl<W> Drop for UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        self.assoc_handle.abort();
    }
}

impl<W> UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer,
        respond_writer: W,
    ) -> UdpAssociation<W> {
        let (assoc_handle, sender) =
            UdpAssociationContext::create(context, peer_addr, keepalive_tx, balancer, respond_writer);
        UdpAssociation {
            assoc_handle,
            sender,
            writer: PhantomData,
        }
    }

    fn try_send(&self, data: (Address, Bytes)) -> io::Result<()> {
        if let Err(..) = self.sender.try_send(data) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err);
        }
        Ok(())
    }
}

struct UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    bypassed_ipv4_socket: Option<ShadowUdpSocket>,
    bypassed_ipv6_socket: Option<ShadowUdpSocket>,
    proxied_socket: Option<MonProxySocket>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    keepalive_flag: bool,
    balancer: PingBalancer,
    respond_writer: W,
}

impl<W> Drop for UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        debug!("udp association for {} is closed", self.peer_addr);
    }
}

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn create(
        context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer,
        respond_writer: W,
    ) -> (JoinHandle<()>, mpsc::Sender<(Address, Bytes)>) {
        // Pending packets UDP_ASSOCIATION_SEND_CHANNEL_SIZE for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        let mut assoc = UdpAssociationContext {
            context,
            peer_addr,
            bypassed_ipv4_socket: None,
            bypassed_ipv6_socket: None,
            proxied_socket: None,
            keepalive_tx,
            keepalive_flag: false,
            balancer,
            respond_writer,
        };
        let handle = tokio::spawn(async move { assoc.dispatch_packet(receiver).await });

        (handle, sender)
    }

    async fn dispatch_packet(&mut self, mut receiver: mpsc::Receiver<(Address, Bytes)>) {
        let mut bypassed_ipv4_buffer = Vec::new();
        let mut bypassed_ipv6_buffer = Vec::new();
        let mut proxied_buffer = Vec::new();
        let mut keepalive_interval = time::interval(Duration::from_secs(1));

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

                received_opt = receive_from_bypassed_opt(&self.bypassed_ipv4_socket, &mut bypassed_ipv4_buffer) => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... (bypassed) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.bypassed_ipv4_socket = None;
                            continue;
                        }
                    };

                    let addr = Address::from(addr);
                    self.send_received_respond_packet(&addr, &bypassed_ipv4_buffer[..n], true).await;
                }

                received_opt = receive_from_bypassed_opt(&self.bypassed_ipv6_socket, &mut bypassed_ipv6_buffer) => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... (bypassed) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.bypassed_ipv6_socket = None;
                            continue;
                        }
                    };

                    let addr = Address::from(addr);
                    self.send_received_respond_packet(&addr, &bypassed_ipv6_buffer[..n], true).await;
                }

                received_opt = receive_from_proxied_opt(&self.proxied_socket, &mut proxied_buffer) => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... (proxied) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.proxied_socket = None;
                            continue;
                        }
                    };

                    self.send_received_respond_packet(&addr, &proxied_buffer[..n], false).await;
                }

                _ = keepalive_interval.tick() => {
                    if self.keepalive_flag {
                        if let Err(..) = self.keepalive_tx.try_send(self.peer_addr) {
                            debug!("udp relay {} keep-alive failed, channel full or closed", self.peer_addr);
                        } else {
                            self.keepalive_flag = false;
                        }
                    }
                }
            }
        }

        #[inline]
        async fn receive_from_bypassed_opt(
            socket: &Option<ShadowUdpSocket>,
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

        #[inline]
        async fn receive_from_proxied_opt(
            socket: &Option<MonProxySocket>,
            buf: &mut Vec<u8>,
        ) -> io::Result<(usize, Address)> {
            match *socket {
                None => future::pending().await,
                Some(ref s) => {
                    if buf.is_empty() {
                        buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                    }
                    s.recv(buf).await
                }
            }
        }
    }

    async fn dispatch_received_packet(&mut self, target_addr: &Address, data: &[u8]) {
        // Check if target should be bypassed. If so, send packets directly.
        let bypassed = self.context.check_target_bypassed(target_addr).await;

        trace!(
            "udp relay {} -> {} ({}) with {} bytes",
            self.peer_addr,
            target_addr,
            if bypassed { "bypassed" } else { "proxied" },
            data.len()
        );

        if bypassed {
            if let Err(err) = self.dispatch_received_bypassed_packet(target_addr, data).await {
                error!(
                    "udp relay {} -> {} (bypassed) with {} bytes, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );
            }
        } else {
            if let Err(err) = self.dispatch_received_proxied_packet(target_addr, data).await {
                error!(
                    "udp relay {} -> {} (proxied) with {} bytes, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );
            }
        }
    }

    async fn dispatch_received_bypassed_packet(&mut self, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        match *target_addr {
            Address::SocketAddress(sa) => self.send_received_bypassed_packet(sa, data).await,
            Address::DomainNameAddress(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |sa| {
                    self.send_received_bypassed_packet(sa, data).await
                })
                .map(|_| ())
            }
        }
    }

    async fn send_received_bypassed_packet(&mut self, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let socket = match target_addr {
            SocketAddr::V4(..) => match self.bypassed_ipv4_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        ShadowUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    self.bypassed_ipv4_socket.insert(socket)
                }
            },
            SocketAddr::V6(..) => match self.bypassed_ipv6_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        ShadowUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    self.bypassed_ipv6_socket.insert(socket)
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

    async fn dispatch_received_proxied_packet(&mut self, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        let socket = match self.proxied_socket {
            Some(ref mut socket) => socket,
            None => {
                // Create a new connection to proxy server

                let server = self.balancer.best_udp_server();
                let svr_cfg = server.server_config();

                let socket =
                    ProxySocket::connect_with_opts(self.context.context(), svr_cfg, self.context.connect_opts_ref())
                        .await?;
                let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());

                self.proxied_socket.insert(socket)
            }
        };

        match socket.send(target_addr, data).await {
            Ok(..) => return Ok(()),
            Err(err) => {
                debug!(
                    "{} -> {} (proxied) sending {} bytes failed, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );

                // Drop the socket and reconnect to another server.
                self.proxied_socket = None;
            }
        }

        Ok(())
    }

    async fn send_received_respond_packet(&mut self, addr: &Address, data: &[u8], bypassed: bool) {
        trace!(
            "udp relay {} <- {} ({}) received {} bytes",
            self.peer_addr,
            addr,
            if bypassed { "bypassed" } else { "proxied" },
            data.len(),
        );

        // Keep association alive in map
        self.keepalive_flag = true;

        // Send back to client
        if let Err(err) = self.respond_writer.send_to(self.peer_addr, addr, data).await {
            warn!(
                "udp failed to send back {} bytes to client {}, from target {} ({}), error: {}",
                data.len(),
                self.peer_addr,
                addr,
                if bypassed { "bypassed" } else { "proxied" },
                err
            );
        } else {
            trace!(
                "udp relay {} <- {} ({}) with {} bytes",
                self.peer_addr,
                addr,
                if bypassed { "bypassed" } else { "proxied" },
                data.len()
            );
        }
    }
}
