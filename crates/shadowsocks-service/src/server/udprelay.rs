//! Shadowsocks UDP server

use std::{
    cell::RefCell,
    io::{self, ErrorKind},
    net::{SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures::future;
use log::{debug, error, info, trace, warn};
use lru_time_cache::LruCache;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use shadowsocks::{
    config::ServerUser,
    crypto::{CipherCategory, CipherKind},
    lookup_then,
    net::{AcceptOpts, AddrFamily, UdpSocket as OutboundUdpSocket},
    relay::{
        socks5::Address,
        udprelay::{options::UdpSocketControlData, ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
    ServerConfig,
};
use tokio::{sync::mpsc, task::JoinHandle, time};

use crate::net::{
    packet_window::PacketWindowFilter,
    utils::to_ipv4_mapped,
    MonProxySocket,
    UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE,
    UDP_ASSOCIATION_SEND_CHANNEL_SIZE,
};

use super::context::ServiceContext;

#[derive(Debug, Clone, Copy)]
enum NatKey {
    PeerAddr(SocketAddr),
    #[cfg(feature = "aead-cipher-2022")]
    SessionId(u64),
}

type AssociationMap = LruCache<SocketAddr, UdpAssociation>;
#[cfg(feature = "aead-cipher-2022")]
type SessionMap = LruCache<u64, UdpAssociation>;

enum NatMap {
    Association(AssociationMap),
    #[cfg(feature = "aead-cipher-2022")]
    Session(SessionMap),
}

impl NatMap {
    fn cleanup_expired(&mut self) {
        match *self {
            NatMap::Association(ref mut m) => {
                m.iter();
            }
            #[cfg(feature = "aead-cipher-2022")]
            NatMap::Session(ref mut m) => {
                m.iter();
            }
        }
    }

    fn keep_alive(&mut self, key: &NatKey) {
        match (self, key) {
            (NatMap::Association(ref mut m), NatKey::PeerAddr(ref peer_addr)) => {
                m.get(peer_addr);
            }
            #[cfg(feature = "aead-cipher-2022")]
            (NatMap::Session(ref mut m), NatKey::SessionId(ref session_id)) => {
                m.get(session_id);
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!("NatMap & NatKey mismatch"),
        }
    }
}

pub struct UdpServer {
    context: Arc<ServiceContext>,
    assoc_map: NatMap,
    keepalive_tx: mpsc::Sender<NatKey>,
    keepalive_rx: mpsc::Receiver<NatKey>,
    time_to_live: Duration,
    accept_opts: AcceptOpts,
    worker_count: usize,
}

impl UdpServer {
    pub fn new(
        context: Arc<ServiceContext>,
        method: CipherKind,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        accept_opts: AcceptOpts,
    ) -> UdpServer {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);

        fn create_assoc_map<K, V>(time_to_live: Duration, capacity: Option<usize>) -> LruCache<K, V>
        where
            K: Ord + Clone,
        {
            match capacity {
                Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
                None => LruCache::with_expiry_duration(time_to_live),
            }
        }

        let assoc_map = match method.category() {
            CipherCategory::None | CipherCategory::Aead => {
                NatMap::Association(create_assoc_map(time_to_live, capacity))
            }
            #[cfg(feature = "stream-cipher")]
            CipherCategory::Stream => NatMap::Association(create_assoc_map(time_to_live, capacity)),
            #[cfg(feature = "aead-cipher-2022")]
            CipherCategory::Aead2022 => NatMap::Session(create_assoc_map(time_to_live, capacity)),
        };

        let (keepalive_tx, keepalive_rx) = mpsc::channel(UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE);

        UdpServer {
            context,
            assoc_map,
            keepalive_tx,
            keepalive_rx,
            time_to_live,
            accept_opts,
            worker_count: 1,
        }
    }

    #[inline]
    pub fn set_worker_count(&mut self, worker_count: usize) {
        self.worker_count = worker_count;
    }

    pub async fn run(mut self, svr_cfg: &ServerConfig) -> io::Result<()> {
        let socket = ProxySocket::bind_with_opts(self.context.context(), svr_cfg, self.accept_opts.clone()).await?;

        info!(
            "shadowsocks udp server listening on {}",
            socket.local_addr().expect("listener.local_addr"),
        );

        let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
        let listener = Arc::new(socket);

        let mut cleanup_timer = time::interval(self.time_to_live);

        let mut orx_opt = None;

        let cpus = self.worker_count;
        let mut other_receivers = Vec::new();
        if cpus > 1 {
            let (otx, orx) = mpsc::channel((cpus - 1) * 16);
            orx_opt = Some(orx);

            other_receivers.reserve(cpus - 1);
            trace!("udp server starting extra {} recv workers", cpus - 1);

            for _ in 1..cpus {
                let otx = otx.clone();
                let listener = listener.clone();
                let context = self.context.clone();

                other_receivers.push(tokio::spawn(async move {
                    let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

                    loop {
                        let (n, peer_addr, target_addr, control) =
                            match UdpServer::recv_one_packet(&context, &listener, &mut buffer).await {
                                Some(s) => s,
                                None => continue,
                            };

                        if let Err(..) = otx
                            .send((peer_addr, target_addr, control, Bytes::copy_from_slice(&buffer[..n])))
                            .await
                        {
                            // If Result is error, the channel receiver is closed. We should exit the task.
                            break;
                        }
                    }
                }));
            }
        }

        struct MulticoreTaskGuard<'a> {
            tasks: &'a mut Vec<JoinHandle<()>>,
        }

        impl Drop for MulticoreTaskGuard<'_> {
            fn drop(&mut self) {
                for task in self.tasks.iter_mut() {
                    task.abort();
                }
            }
        }

        let _guard = MulticoreTaskGuard {
            tasks: &mut other_receivers,
        };

        type QueuedDataType = (SocketAddr, Address, Option<UdpSocketControlData>, Bytes);

        #[inline]
        async fn multicore_recv(orx_opt: &mut Option<mpsc::Receiver<QueuedDataType>>) -> QueuedDataType {
            match orx_opt {
                None => future::pending().await,
                Some(ref mut orx) => match orx.recv().await {
                    Some(t) => t,
                    None => unreachable!("multicore sender should keep at least 1"),
                },
            }
        }

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            tokio::select! {
                _ = cleanup_timer.tick() => {
                    // cleanup expired associations. iter() will remove expired elements
                    self.assoc_map.cleanup_expired();
                }

                peer_addr_opt = self.keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                    self.assoc_map.keep_alive(&peer_addr);
                }

                recv_result = UdpServer::recv_one_packet(&self.context, &listener, &mut buffer) => {
                    let (n, peer_addr, target_addr, control) = match recv_result {
                        Some(s) => s,
                        None => continue,
                    };

                    let data = &buffer[..n];
                    if let Err(err) = self.send_packet(&listener, peer_addr, target_addr, control, Bytes::copy_from_slice(data)).await {
                        debug!(
                            "udp packet relay {} with {} bytes failed, error: {}",
                            peer_addr,
                            data.len(),
                            err
                        );
                    }
                }

                recv_result = multicore_recv(&mut orx_opt), if orx_opt.is_some() => {
                    let (peer_addr, target_addr, control, data) = recv_result;
                    let data_len = data.len();
                    if let Err(err) = self.send_packet(&listener, peer_addr, target_addr, control, data).await {
                        debug!(
                            "udp packet relay {} with {} bytes failed, error: {}",
                            peer_addr,
                            data_len,
                            err
                        );
                    }
                }
            }
        }
    }

    async fn recv_one_packet(
        context: &ServiceContext,
        l: &MonProxySocket,
        buffer: &mut [u8],
    ) -> Option<(usize, SocketAddr, Address, Option<UdpSocketControlData>)> {
        let (n, peer_addr, target_addr, control) = match l.recv_from_with_ctrl(buffer).await {
            Ok(s) => s,
            Err(err) => {
                error!("udp server recv packet failed. {}", err);
                return None;
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
            return None;
        }

        if context.check_client_blocked(&peer_addr) {
            warn!(
                "udp client {} outbound {} access denied by ACL rules",
                peer_addr, target_addr
            );
            return None;
        }

        if context.check_outbound_blocked(&target_addr).await {
            warn!("udp client {} outbound {} blocked by ACL rules", peer_addr, target_addr);
            return None;
        }

        Some((n, peer_addr, target_addr, control))
    }

    async fn send_packet(
        &mut self,
        listener: &Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        target_addr: Address,
        control: Option<UdpSocketControlData>,
        data: Bytes,
    ) -> io::Result<()> {
        match self.assoc_map {
            NatMap::Association(ref mut m) => {
                if let Some(assoc) = m.get(&peer_addr) {
                    return assoc.try_send((peer_addr, target_addr, data, control));
                }

                let assoc = UdpAssociation::new_association(
                    self.context.clone(),
                    listener.clone(),
                    peer_addr,
                    self.keepalive_tx.clone(),
                );

                debug!("created udp association for {}", peer_addr);

                assoc.try_send((peer_addr, target_addr, data, control))?;
                m.insert(peer_addr, assoc);
            }
            #[cfg(feature = "aead-cipher-2022")]
            NatMap::Session(ref mut m) => {
                let xcontrol = match control {
                    None => {
                        error!("control is required for session based NAT, from {}", peer_addr);
                        return Err(io::Error::new(ErrorKind::Other, "control data missing in packet"));
                    }
                    Some(ref c) => c,
                };

                let client_session_id = xcontrol.client_session_id;

                if let Some(assoc) = m.get(&client_session_id) {
                    return assoc.try_send((peer_addr, target_addr, data, control));
                }

                let assoc = UdpAssociation::new_session(
                    self.context.clone(),
                    listener.clone(),
                    peer_addr,
                    self.keepalive_tx.clone(),
                    client_session_id,
                );

                debug!(
                    "created udp association for {} with session {}",
                    peer_addr, client_session_id
                );

                assoc.try_send((peer_addr, target_addr, data, control))?;
                m.insert(client_session_id, assoc);
            }
        }

        Ok(())
    }
}

type UdpAssociationSendMessage = (SocketAddr, Address, Bytes, Option<UdpSocketControlData>);

struct UdpAssociation {
    assoc_handle: JoinHandle<()>,
    sender: mpsc::Sender<UdpAssociationSendMessage>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.assoc_handle.abort();
    }
}

impl UdpAssociation {
    fn new_association(
        context: Arc<ServiceContext>,
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<NatKey>,
    ) -> UdpAssociation {
        let (assoc_handle, sender) = UdpAssociationContext::create(context, inbound, peer_addr, keepalive_tx, None);
        UdpAssociation { assoc_handle, sender }
    }

    #[cfg(feature = "aead-cipher-2022")]
    fn new_session(
        context: Arc<ServiceContext>,
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<NatKey>,
        client_session_id: u64,
    ) -> UdpAssociation {
        let (assoc_handle, sender) =
            UdpAssociationContext::create(context, inbound, peer_addr, keepalive_tx, Some(client_session_id));
        UdpAssociation { assoc_handle, sender }
    }

    fn try_send(&self, data: UdpAssociationSendMessage) -> io::Result<()> {
        if let Err(..) = self.sender.try_send(data) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err);
        }
        Ok(())
    }
}

struct ClientSessionContext {
    client_session_id: u64,
    packet_window_filter: PacketWindowFilter,
    client_user: Option<Arc<ServerUser>>,
}

impl ClientSessionContext {
    fn new(client_session_id: u64) -> ClientSessionContext {
        ClientSessionContext {
            client_session_id,
            packet_window_filter: PacketWindowFilter::new(),
            client_user: None,
        }
    }
}

struct UdpAssociationContext {
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    outbound_ipv4_socket: Option<OutboundUdpSocket>,
    outbound_ipv6_socket: Option<OutboundUdpSocket>,
    keepalive_tx: mpsc::Sender<NatKey>,
    keepalive_flag: bool,
    inbound: Arc<MonProxySocket>,
    // AEAD 2022
    client_session: Option<ClientSessionContext>,
    server_session_id: u64,
    server_packet_id: u64,
}

impl Drop for UdpAssociationContext {
    fn drop(&mut self) {
        debug!("udp association for {} is closed", self.peer_addr);
    }
}

thread_local! {
    static CLIENT_SESSION_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
}

#[inline]
fn generate_server_session_id() -> u64 {
    CLIENT_SESSION_RNG.with(|rng| rng.borrow_mut().gen())
}

impl UdpAssociationContext {
    fn create(
        context: Arc<ServiceContext>,
        inbound: Arc<MonProxySocket>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<NatKey>,
        client_session_id: Option<u64>,
    ) -> (JoinHandle<()>, mpsc::Sender<UdpAssociationSendMessage>) {
        // Pending packets UDP_ASSOCIATION_SEND_CHANNEL_SIZE for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        let mut assoc = UdpAssociationContext {
            context,
            peer_addr,
            outbound_ipv4_socket: None,
            outbound_ipv6_socket: None,
            keepalive_tx,
            keepalive_flag: false,
            inbound,
            client_session: client_session_id.map(ClientSessionContext::new),
            // server_session_id must be generated randomly
            server_session_id: generate_server_session_id(),
            server_packet_id: 0,
        };
        let handle = tokio::spawn(async move { assoc.dispatch_packet(receiver).await });

        (handle, sender)
    }

    async fn dispatch_packet(&mut self, mut receiver: mpsc::Receiver<UdpAssociationSendMessage>) {
        let mut outbound_ipv4_buffer = Vec::new();
        let mut outbound_ipv6_buffer = Vec::new();
        let mut keepalive_interval = time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                packet_received_opt = receiver.recv() => {
                    let (peer_addr, target_addr, data, control) = match packet_received_opt {
                        Some(d) => d,
                        None => {
                            trace!("udp association for {} -> ... channel closed", self.peer_addr);
                            break;
                        }
                    };

                    self.dispatch_received_packet(peer_addr, &target_addr, &data, &control).await;
                }

                received_opt = receive_from_outbound_opt(&self.outbound_ipv4_socket, &mut outbound_ipv4_buffer), if self.outbound_ipv4_socket.is_some() => {
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
                    self.send_received_respond_packet(addr, &outbound_ipv4_buffer[..n]).await;
                }

                received_opt = receive_from_outbound_opt(&self.outbound_ipv6_socket, &mut outbound_ipv6_buffer), if self.outbound_ipv6_socket.is_some() => {
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
                    self.send_received_respond_packet(addr, &outbound_ipv6_buffer[..n]).await;
                }

                _ = keepalive_interval.tick() => {
                    if self.keepalive_flag {
                        let nat_key = match self.client_session {
                            None => NatKey::PeerAddr(self.peer_addr),
                            #[cfg(feature = "aead-cipher-2022")]
                            Some(ref s) => NatKey::SessionId(s.client_session_id),
                            #[cfg(not(feature = "aead-cipher-2022"))]
                            Some(..) => unreachable!("client_session_id is not None but aead-cipher-2022 is not enabled"),
                        };

                        if let Err(..) = self.keepalive_tx.try_send(nat_key) {
                            debug!("udp relay {:?} keep-alive failed, channel full or closed", nat_key);
                        } else {
                            self.keepalive_flag = false;
                        }
                    }
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

    async fn dispatch_received_packet(
        &mut self,
        peer_addr: SocketAddr,
        target_addr: &Address,
        data: &[u8],
        control: &Option<UdpSocketControlData>,
    ) {
        if let Some(ref mut session) = self.client_session {
            if peer_addr != self.peer_addr {
                debug!(
                    "udp relay for {} changed to {}, session: {:?}",
                    self.peer_addr, peer_addr, session.client_session_id
                );
                self.peer_addr = peer_addr;
            }
        }

        trace!(
            "udp relay {} -> {} with {} bytes, control: {:?}",
            self.peer_addr,
            target_addr,
            data.len(),
            control,
        );

        if self.context.check_outbound_blocked(target_addr).await {
            error!(
                "udp client {} outbound {} blocked by ACL rules",
                self.peer_addr, target_addr
            );
            return;
        }

        if let Some(control) = control {
            // Check if Packet ID is in the window

            let session_context = self
                .client_session
                .get_or_insert_with(|| ClientSessionContext::new(control.client_session_id));

            let packet_id = control.packet_id;
            if !session_context
                .packet_window_filter
                .validate_packet_id(packet_id, u64::MAX)
            {
                error!("udp client {} packet_id {} out of window", self.peer_addr, packet_id);
                return;
            }

            session_context.client_user = control.user.clone();
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

    async fn send_received_outbound_packet(&mut self, mut target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        const UDP_SOCKET_SUPPORT_DUAL_STACK: bool = cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "freebsd",
            // target_os = "dragonfly",
            // target_os = "netbsd",
            target_os = "windows",
        ));

        let socket = if UDP_SOCKET_SUPPORT_DUAL_STACK {
            match self.outbound_ipv6_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        OutboundUdpSocket::connect_any_with_opts(AddrFamily::Ipv6, self.context.connect_opts_ref())
                            .await?;
                    self.outbound_ipv6_socket.insert(socket)
                }
            }
        } else {
            match target_addr {
                SocketAddr::V4(..) => match self.outbound_ipv4_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket =
                            OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref())
                                .await?;
                        self.outbound_ipv4_socket.insert(socket)
                    }
                },
                SocketAddr::V6(..) => match self.outbound_ipv6_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket =
                            OutboundUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref())
                                .await?;
                        self.outbound_ipv6_socket.insert(socket)
                    }
                },
            }
        };

        if UDP_SOCKET_SUPPORT_DUAL_STACK {
            if let SocketAddr::V4(saddr) = target_addr {
                let mapped_ip = saddr.ip().to_ipv6_mapped();
                target_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, saddr.port(), 0, 0));
            }
        }

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

    async fn send_received_respond_packet(&mut self, mut addr: Address, data: &[u8]) {
        trace!("udp relay {} <- {} received {} bytes", self.peer_addr, addr, data.len());

        // Keep association alive in map
        self.keepalive_flag = true;

        // Convert IPv4-mapped-IPv6 to IPv4
        //
        // It is an undefined behavior in shadowsocks' protocol about how to handle IPv4-mapped-IPv6.
        // But for some implementations, they may expect the target address to be IPv4, because
        // the peer address is IPv4 when calling `sendto`.
        if let Address::SocketAddress(SocketAddr::V6(ref v6)) = addr {
            if let Some(v4) = to_ipv4_mapped(v6.ip()) {
                addr = Address::SocketAddress(SocketAddr::new(v4.into(), v6.port()));
            }
        }

        match self.client_session {
            None => {
                // Naive route, send data directly back to client without session
                if let Err(err) = self.inbound.send_to(self.peer_addr, &addr, data).await {
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
            Some(ref client_session) => {
                // AEAD 2022, client session

                // Increase Packet ID before send
                self.server_packet_id = match self.server_packet_id.checked_add(1) {
                    Some(i) => i,
                    None => {
                        // FIXME: server_packet_id overflowed. There is no way to recover from this error.
                        //
                        // Application clients may open a new session when it couldn't receive proper respond.

                        warn!(
                            "udp failed to send back {} bytes to client {}, from target {}, server packet id overflowed",
                            data.len(),
                            self.peer_addr,
                            addr
                        );
                        return;
                    }
                };

                let mut control = UdpSocketControlData::default();
                control.client_session_id = client_session.client_session_id;
                control.server_session_id = self.server_session_id;
                control.packet_id = self.server_packet_id;
                control.user = client_session.client_user.clone();

                if let Err(err) = self
                    .inbound
                    .send_to_with_ctrl(self.peer_addr, &addr, &control, data)
                    .await
                {
                    warn!(
                        "udp failed to send back {} bytes to client {}, from target {}, control: {:?}, error: {}",
                        data.len(),
                        self.peer_addr,
                        addr,
                        control,
                        err
                    );
                } else {
                    trace!(
                        "udp relay {} <- {} with {} bytes, control {:?}",
                        self.peer_addr,
                        addr,
                        data.len(),
                        control
                    );
                }
            }
        }
    }
}
