//! UDP Tunnel server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures::future;
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
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time};

use crate::{
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE, UDP_ASSOCIATION_SEND_CHANNEL_SIZE},
    },
    net::MonProxySocket,
};

type AssociationMap = LruCache<SocketAddr, UdpAssociation>;

pub struct UdpTunnel {
    context: Arc<ServiceContext>,
    assoc_map: AssociationMap,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    keepalive_rx: mpsc::Receiver<SocketAddr>,
    time_to_live: Duration,
}

impl UdpTunnel {
    pub fn new(context: Arc<ServiceContext>, time_to_live: Option<Duration>, capacity: Option<usize>) -> UdpTunnel {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = match capacity {
            Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            None => LruCache::with_expiry_duration(time_to_live),
        };

        let (keepalive_tx, keepalive_rx) = mpsc::channel(UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE);

        UdpTunnel {
            context,
            assoc_map,
            keepalive_tx,
            keepalive_rx,
            time_to_live,
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
        let mut cleanup_timer = time::interval(self.time_to_live);

        loop {
            tokio::select! {
                _ = cleanup_timer.tick() => {
                    // cleanup expired associations. iter() will remove expired elements
                    let _ = self.assoc_map.iter();
                }

                peer_addr_opt = self.keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                    self.assoc_map.get(&peer_addr);
                }

                recv_result = listener.recv_from(&mut buffer) => {
                    let (n, peer_addr) = match recv_result {
                        Ok(s) => s,
                        Err(err) => {
                            error!("udp server recv_from failed with error: {}", err);
                            time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                    };

                    if n == 0 {
                        // For windows, it will generate a ICMP Port Unreachable Message
                        // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
                        // Which will result in recv_from return 0.
                        //
                        // It cannot be solved here, because `WSAGetLastError` is already set.
                        //
                        // See `relay::udprelay::utils::create_socket` for more detail.
                        continue;
                    }

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
        if let Some(assoc) = self.assoc_map.get(&peer_addr) {
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

        debug!("created udp association for {}", peer_addr);

        assoc.try_send(Bytes::copy_from_slice(data))?;
        self.assoc_map.insert(peer_addr, assoc);

        Ok(())
    }
}

struct UdpAssociation {
    assoc_handle: JoinHandle<()>,
    sender: mpsc::Sender<Bytes>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.assoc_handle.abort();
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
        let (assoc_handle, sender) =
            UdpAssociationContext::create(context, inbound, peer_addr, forward_addr, keepalive_tx, balancer);
        UdpAssociation { assoc_handle, sender }
    }

    fn try_send(&self, data: Bytes) -> io::Result<()> {
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
    forward_addr: Address,
    proxied_socket: Option<MonProxySocket>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    keepalive_flag: bool,
    balancer: PingBalancer,
    inbound: Arc<UdpSocket>,
}

impl Drop for UdpAssociationContext {
    fn drop(&mut self) {
        debug!("udp association for {} is closed", self.peer_addr);
    }
}

impl UdpAssociationContext {
    fn create(
        context: Arc<ServiceContext>,
        inbound: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        forward_addr: Address,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer,
    ) -> (JoinHandle<()>, mpsc::Sender<Bytes>) {
        // Pending packets UDP_ASSOCIATION_SEND_CHANNEL_SIZE for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        let mut assoc = UdpAssociationContext {
            context,
            peer_addr,
            forward_addr,
            proxied_socket: None,
            keepalive_tx,
            keepalive_flag: false,
            balancer,
            inbound,
        };
        let handle = tokio::spawn(async move { assoc.dispatch_packet(receiver).await });

        (handle, sender)
    }

    async fn dispatch_packet(&mut self, mut receiver: mpsc::Receiver<Bytes>) {
        let mut proxied_buffer = Vec::new();
        let mut keepalive_interval = time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                packet_received_opt = receiver.recv() => {
                    let data = match packet_received_opt {
                        Some(d) => d,
                        None => {
                            trace!("udp association for {} -> ... channel closed", self.peer_addr);
                            break;
                        }
                    };

                    self.dispatch_received_packet(&data).await;
                }

                received_opt = receive_from_proxied_opt(&self.proxied_socket, &mut proxied_buffer) => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.proxied_socket = None;
                            continue;
                        }
                    };

                    self.send_received_respond_packet(&addr, &proxied_buffer[..n]).await;
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

    async fn dispatch_received_packet(&mut self, data: &[u8]) {
        trace!(
            "udp relay {} -> {} with {} bytes",
            self.peer_addr,
            self.forward_addr,
            data.len()
        );

        if let Err(err) = self.dispatch_received_proxied_packet(data).await {
            error!(
                "udp relay {} -> {} with {} bytes, error: {}",
                self.peer_addr,
                self.forward_addr,
                data.len(),
                err
            );
        }
    }

    async fn dispatch_received_proxied_packet(&mut self, data: &[u8]) -> io::Result<()> {
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

        match socket.send(&self.forward_addr, data).await {
            Ok(..) => return Ok(()),
            Err(err) => {
                debug!(
                    "{} -> {} (proxied) sending {} bytes failed, error: {}",
                    self.peer_addr,
                    self.forward_addr,
                    data.len(),
                    err
                );

                // Drop the socket and reconnect to another server.
                self.proxied_socket = None;
            }
        }

        Ok(())
    }

    async fn send_received_respond_packet(&mut self, addr: &Address, data: &[u8]) {
        trace!("udp relay {} <- {} received {} bytes", self.peer_addr, addr, data.len());

        // Keep association alive in map
        self.keepalive_flag = true;

        // Send back to client
        if let Err(err) = self.inbound.send_to(data, self.peer_addr).await {
            warn!(
                "udp failed to send back {} bytes to client {}, from target {}, error: {}",
                data.len(),
                self.peer_addr,
                addr,
                err
            );
        } else {
            trace!("udp relay {} <- {} with {} bytes", self.peer_addr, addr, data.len());
        }
    }
}
