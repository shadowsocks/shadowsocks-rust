//! UDP transparent proxy

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures::future::{self, AbortHandle};
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
use spin::Mutex as SpinMutex;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    config::{ClientConfig, RedirType},
    local::{context::ServiceContext, loadbalancing::PingBalancer, redir::redir_ext::UdpSocketRedirExt},
    net::MonProxySocket,
};

use self::sys::UdpRedirSocket;

mod sys;

pub struct UdpRedir {
    context: Arc<ServiceContext>,
    redir_ty: RedirType,
    assoc_map: Arc<Mutex<LruCache<SocketAddr, UdpAssociation>>>,
    cleanup_abortable: AbortHandle,
}

impl Drop for UdpRedir {
    fn drop(&mut self) {
        self.cleanup_abortable.abort();
    }
}

impl UdpRedir {
    pub fn new(
        context: Arc<ServiceContext>,
        redir_ty: RedirType,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
    ) -> UdpRedir {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = Arc::new(Mutex::new(match capacity {
            Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            None => LruCache::with_expiry_duration(time_to_live),
        }));

        let cleanup_abortable = {
            let assoc_map = assoc_map.clone();
            let (cleanup_task, cleanup_abortable) = future::abortable(async move {
                loop {
                    time::sleep(time_to_live).await;

                    // iter() will trigger a cleanup of expired associations
                    let _ = assoc_map.lock().await.iter();
                }
            });
            tokio::spawn(cleanup_task);
            cleanup_abortable
        };

        UdpRedir {
            context,
            redir_ty,
            assoc_map,
            cleanup_abortable,
        }
    }

    pub async fn run(&mut self, client_config: &ClientConfig, balancer: PingBalancer) -> io::Result<()> {
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

        let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (recv_len, src, dst) = match listener.recv_dest_from(&mut pkt_buf).await {
                Ok(o) => o,
                Err(err) => {
                    error!("recv_dest_from failed with err: {}", err);
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

            if let Err(err) = self.send_packet(src, dst, &balancer, pkt).await {
                error!(
                    "udp packet relay {} -> {} with {} bytes failed, error: {}",
                    src,
                    dst,
                    pkt.len(),
                    err
                );
            }
        }
    }

    async fn send_packet(
        &mut self,
        peer_addr: SocketAddr,
        target_addr: SocketAddr,
        balancer: &PingBalancer,
        data: &[u8],
    ) -> io::Result<()> {
        // Check or (re)create an association
        match self.assoc_map.lock().await.entry(peer_addr) {
            Entry::Occupied(occ) => {
                let assoc = occ.into_mut();
                assoc.try_send((target_addr, Bytes::copy_from_slice(data)))
            }
            Entry::Vacant(vac) => {
                let assoc = vac.insert(UdpAssociation::new(
                    self.context.clone(),
                    self.redir_ty,
                    peer_addr,
                    self.assoc_map.clone(),
                    balancer.clone(),
                ));
                trace!("created udp association for {}", peer_addr);
                assoc.try_send((target_addr, Bytes::copy_from_slice(data)))
            }
        }
    }
}

struct UdpAssociation {
    assoc: Arc<UdpAssociationContext>,
    sender: mpsc::Sender<(SocketAddr, Bytes)>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.assoc.bypassed_ipv4_socket.lock().abort();
        self.assoc.bypassed_ipv6_socket.lock().abort();
        self.assoc.proxied_socket.lock().abort();
    }
}

impl UdpAssociation {
    fn new(
        context: Arc<ServiceContext>,
        redir_ty: RedirType,
        peer_addr: SocketAddr,
        assoc_map: Arc<Mutex<LruCache<SocketAddr, UdpAssociation>>>,
        balancer: PingBalancer,
    ) -> UdpAssociation {
        let (assoc, sender) = UdpAssociationContext::new(context, redir_ty, peer_addr, assoc_map, balancer);
        UdpAssociation { assoc, sender }
    }

    fn try_send(&self, data: (SocketAddr, Bytes)) -> io::Result<()> {
        if let Err(..) = self.sender.try_send(data) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err);
        }
        Ok(())
    }
}

enum UdpAssociationBypassState {
    Empty,
    Connected {
        socket: Arc<UdpSocket>,
        abortable: AbortHandle,
    },
    Aborted,
}

impl Drop for UdpAssociationBypassState {
    fn drop(&mut self) {
        if let UdpAssociationBypassState::Connected { ref abortable, .. } = *self {
            abortable.abort();
        }
    }
}

impl UdpAssociationBypassState {
    fn empty() -> UdpAssociationBypassState {
        UdpAssociationBypassState::Empty
    }

    fn set_connected(&mut self, socket: Arc<UdpSocket>, abortable: AbortHandle) {
        *self = UdpAssociationBypassState::Connected { socket, abortable };
    }

    fn abort(&mut self) {
        *self = UdpAssociationBypassState::Aborted;
    }
}

enum UdpAssociationProxyState {
    Empty,
    Connected {
        socket: Arc<MonProxySocket>,
        abortable: AbortHandle,
    },
    Aborted,
}

impl Drop for UdpAssociationProxyState {
    fn drop(&mut self) {
        if let UdpAssociationProxyState::Connected { ref abortable, .. } = *self {
            abortable.abort();
        }
    }
}

impl UdpAssociationProxyState {
    fn empty() -> UdpAssociationProxyState {
        UdpAssociationProxyState::Empty
    }

    fn reset(&mut self) {
        *self = UdpAssociationProxyState::Empty;
    }

    fn set_connected(&mut self, socket: Arc<MonProxySocket>, abortable: AbortHandle) {
        *self = UdpAssociationProxyState::Connected { socket, abortable };
    }

    fn abort(&mut self) {
        *self = UdpAssociationProxyState::Aborted;
    }
}

struct UdpAssociationContext {
    context: Arc<ServiceContext>,
    redir_ty: RedirType,
    peer_addr: SocketAddr,
    bypassed_ipv4_socket: SpinMutex<UdpAssociationBypassState>,
    bypassed_ipv6_socket: SpinMutex<UdpAssociationBypassState>,
    proxied_socket: SpinMutex<UdpAssociationProxyState>,
    assoc_map: Arc<Mutex<LruCache<SocketAddr, UdpAssociation>>>,
    balancer: PingBalancer,
}

impl Drop for UdpAssociationContext {
    fn drop(&mut self) {
        trace!("udp association for {} is closed", self.peer_addr);
    }
}

impl UdpAssociationContext {
    fn new(
        context: Arc<ServiceContext>,
        redir_ty: RedirType,
        peer_addr: SocketAddr,
        assoc_map: Arc<Mutex<LruCache<SocketAddr, UdpAssociation>>>,
        balancer: PingBalancer,
    ) -> (Arc<UdpAssociationContext>, mpsc::Sender<(SocketAddr, Bytes)>) {
        // Pending packets 1024 should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping exccess packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(1024);

        let assoc = Arc::new(UdpAssociationContext {
            context,
            redir_ty,
            peer_addr,
            bypassed_ipv4_socket: SpinMutex::new(UdpAssociationBypassState::empty()),
            bypassed_ipv6_socket: SpinMutex::new(UdpAssociationBypassState::empty()),
            proxied_socket: SpinMutex::new(UdpAssociationProxyState::empty()),
            assoc_map,
            balancer,
        });

        let l2r_task = {
            let assoc = assoc.clone();
            assoc.copy_l2r(receiver)
        };
        tokio::spawn(l2r_task);

        (assoc, sender)
    }

    async fn copy_l2r(self: Arc<Self>, mut receiver: mpsc::Receiver<(SocketAddr, Bytes)>) {
        while let Some((target_addr, data)) = receiver.recv().await {
            let bypassed = self.context.check_target_bypassed(&Address::from(target_addr)).await;

            trace!(
                "udp relay {} -> {} ({}) with {} bytes",
                self.peer_addr,
                target_addr,
                if bypassed { "bypassed" } else { "proxied" },
                data.len()
            );

            let assoc = self.clone();
            if bypassed {
                if let Err(err) = assoc.copy_bypassed_l2r(target_addr, &data).await {
                    error!(
                        "udp relay {} -> {} (bypassed) with {} bytes, error: {}",
                        self.peer_addr,
                        target_addr,
                        data.len(),
                        err
                    );
                }
            } else {
                if let Err(err) = assoc.copy_proxied_l2r(target_addr, &data).await {
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
    }

    async fn copy_bypassed_l2r(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        match target_addr {
            SocketAddr::V4(..) => self.copy_bypassed_ipv4_l2r(target_addr, data).await,
            SocketAddr::V6(..) => self.copy_bypassed_ipv6_l2r(target_addr, data).await,
        }
    }

    async fn copy_bypassed_ipv4_l2r(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let socket = {
            let mut handle = self.bypassed_ipv4_socket.lock();

            match *handle {
                UdpAssociationBypassState::Empty => {
                    // Create a new connection to proxy server

                    let socket =
                        ShadowUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    let socket: Arc<UdpSocket> = Arc::new(socket.into());

                    let (r2l_fut, r2l_abortable) = {
                        let assoc = self.clone();
                        future::abortable(assoc.copy_bypassed_r2l(socket.clone()))
                    };

                    // CLIENT <- REMOTE
                    tokio::spawn(r2l_fut);
                    debug!(
                        "created udp association for {} (bypassed) with {:?}",
                        self.peer_addr,
                        self.context.connect_opts_ref()
                    );

                    handle.set_connected(socket.clone(), r2l_abortable);
                    socket
                }
                UdpAssociationBypassState::Connected { ref socket, .. } => socket.clone(),
                UdpAssociationBypassState::Aborted => {
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

    async fn copy_bypassed_ipv6_l2r(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let socket = {
            let mut handle = self.bypassed_ipv6_socket.lock();

            match *handle {
                UdpAssociationBypassState::Empty => {
                    // Create a new connection to proxy server

                    let socket =
                        ShadowUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
                    let socket: Arc<UdpSocket> = Arc::new(socket.into());

                    let (r2l_fut, r2l_abortable) = {
                        let assoc = self.clone();
                        future::abortable(assoc.copy_bypassed_r2l(socket.clone()))
                    };

                    // CLIENT <- REMOTE
                    tokio::spawn(r2l_fut);
                    debug!(
                        "created udp association for {} (bypassed) with {:?}",
                        self.peer_addr,
                        self.context.connect_opts_ref()
                    );

                    handle.set_connected(socket.clone(), r2l_abortable);
                    socket
                }
                UdpAssociationBypassState::Connected { ref socket, .. } => socket.clone(),
                UdpAssociationBypassState::Aborted => {
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

    async fn copy_proxied_l2r(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let mut last_err = io::Error::new(ErrorKind::Other, "udp relay sendto failed after retry");

        for tried in 0..3 {
            let socket = {
                let mut handle = self.proxied_socket.lock();

                match *handle {
                    UdpAssociationProxyState::Empty => {
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

                        let (r2l_fut, r2l_abortable) = {
                            let assoc = self.clone();
                            future::abortable(assoc.copy_proxied_r2l(socket.clone()))
                        };

                        // CLIENT <- REMOTE
                        tokio::spawn(r2l_fut);

                        debug!(
                            "created udp association for {} <-> {} (proxied) with {:?}",
                            self.peer_addr,
                            svr_cfg.addr(),
                            self.context.connect_opts_ref()
                        );

                        handle.set_connected(socket.clone(), r2l_abortable);
                        socket
                    }
                    UdpAssociationProxyState::Connected { ref socket, .. } => socket.clone(),
                    UdpAssociationProxyState::Aborted => {
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

            let target_addr = Address::from(target_addr);
            match socket.send(&target_addr, data).await {
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
            let (n, addr) = match outbound.recv(&mut buffer).await {
                Ok(n) => {
                    // Keep association alive in map
                    let _ = self.assoc_map.lock().await.get(&self.peer_addr);
                    n
                }
                Err(err) => {
                    // Socket that connected to remote server returns an error, it should be ECONNREFUSED in most cases.
                    // That indicates that the association on the server side have been dropped.
                    //
                    // There is no point to keep this socket. Drop it immediately.
                    self.proxied_socket.lock().reset();

                    error!(
                        "udp failed to receive from proxied outbound socket, peer_addr: {}, error: {}",
                        self.peer_addr, err
                    );
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // Create a transparent socket binds to that `addr` and send back to clients
            //
            // XXX: addr must not be a domain name address
            let addr = match addr {
                Address::SocketAddress(sa) => sa,
                Address::DomainNameAddress(..) => {
                    error!(
                        "received proxied packet {} <- {}, redir doesn't allow binding to a domain name address",
                        self.peer_addr, addr
                    );
                    continue;
                }
            };

            // Create a socket binds to destination addr
            // This only works for systems that supports binding to non-local addresses
            let inbound = match UdpRedirSocket::bind(self.redir_ty, addr) {
                Ok(s) => s,
                Err(err) => {
                    error!(
                        "failed to bind to dest {} for sending back to {}, error: {}",
                        addr, self.peer_addr, err
                    );
                    continue;
                }
            };

            // Send back to client
            if let Err(err) = inbound.send_to(data, self.peer_addr).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    self.peer_addr, addr, err
                );
                continue;
            }

            trace!("udp relay {} <- {} with {} bytes", self.peer_addr, addr, data.len());
        }
    }

    async fn copy_bypassed_r2l(self: Arc<Self>, outbound: Arc<UdpSocket>) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, addr) = match outbound.recv_from(&mut buffer).await {
                Ok(n) => {
                    // Keep association alive in map
                    let _ = self.assoc_map.lock().await.get(&self.peer_addr);
                    n
                }
                Err(err) => {
                    error!(
                        "udp failed to receive from bypass outbound socket, peer_addr: {}, error: {}",
                        self.peer_addr, err
                    );
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // Create a socket binds to destination addr
            // This only works for systems that supports binding to non-local addresses
            let inbound = UdpRedirSocket::bind(self.redir_ty, addr)?;

            // Send back to client
            if let Err(err) = inbound.send_to(data, self.peer_addr).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    self.peer_addr, addr, err
                );
            }

            trace!("udp relay {} <- {} with {} bytes", self.peer_addr, addr, data.len());
        }
    }
}
