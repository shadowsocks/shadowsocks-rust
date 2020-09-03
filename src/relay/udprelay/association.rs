//! UDP Association
//!
//! Working like a NAT proxy

#![allow(dead_code)]

use std::{
    future::Future,
    io::{self, Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::future::{self, AbortHandle};
use log::{debug, error, warn};
use lru_time_cache::{Entry, LruCache};
use tokio::{
    self,
    net::{
        udp::{RecvHalf, SendHalf},
        UdpSocket,
    },
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    config::{Config, ServerAddr, ServerConfig},
    context::{Context, SharedContext},
    crypto::CipherCategory,
    relay::{
        loadbalancing::server::{ServerData, SharedServerStatistic},
        socks5::Address,
        sys::{create_udp_socket, create_udp_socket_with_context},
        utils::try_timeout,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

#[async_trait]
pub trait ProxySend {
    async fn send_packet(&mut self, addr: Address, data: Vec<u8>) -> io::Result<()>;
}

pub struct ProxyAssociation {
    tx: mpsc::Sender<(Address, Vec<u8>)>,
    watchers: Vec<AbortHandle>,
}

impl Drop for ProxyAssociation {
    fn drop(&mut self) {
        for watcher in &self.watchers {
            watcher.abort();
        }
    }
}

impl ProxyAssociation {
    pub async fn associate_proxied<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
    ) -> io::Result<ProxyAssociation>
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        let remote_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let remote_bind_addr = remote_udp.local_addr().expect("determine port bound to");

        debug!("created UDP association {} <-> {}", src_addr, remote_bind_addr);

        // connect() to remote server to avoid resolving server's address every call of send()
        // ref: #263
        ProxyAssociation::connect_remote(server.context(), server.server_config(), &remote_udp).await?;

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (remote_receiver, remote_sender) = remote_udp.split();

        // LOCAL -> REMOTE task
        // All packets will be sent directly to proxy
        tokio::spawn(Self::l2r_packet_proxied(src_addr, server.clone(), rx, remote_sender));

        // REMOTE <- LOCAL task
        let remote_watcher = Self::r2l_packet_abortable(src_addr, server, sender, remote_receiver, false);
        let watchers = vec![remote_watcher];

        Ok(ProxyAssociation { tx, watchers })
    }

    pub async fn associate_bypassed<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
    ) -> io::Result<ProxyAssociation>
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        let remote_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let remote_bind_addr = remote_udp.local_addr().expect("determine port bound to");

        debug!("created UDP association {} <-> {}", src_addr, remote_bind_addr);

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (remote_receiver, remote_sender) = remote_udp.split();

        // LOCAL -> REMOTE task
        // All packets will be sent directly to proxy
        tokio::spawn(Self::l2r_packet_bypassed(src_addr, server.clone(), rx, remote_sender));

        // REMOTE <- LOCAL task
        let remote_watcher = Self::r2l_packet_abortable(src_addr, server, sender, remote_receiver, true);
        let watchers = vec![remote_watcher];

        Ok(ProxyAssociation { tx, watchers })
    }

    pub async fn associate_with_acl<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
    ) -> io::Result<ProxyAssociation>
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Clone + Send + 'static,
    {
        // Proxies everything if there is no ACL configured.
        if server.context().acl().is_none() {
            return ProxyAssociation::associate_proxied(src_addr, server, sender).await;
        }

        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        let remote_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let remote_bind_addr = remote_udp.local_addr().expect("determine port bound to");

        // connect() to remote server to avoid resolving server's address every call of send()
        // ref: #263
        ProxyAssociation::connect_remote(server.context(), server.server_config(), &remote_udp).await?;

        // A socket for bypassed
        let bypass_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let bypass_bind_addr = bypass_udp.local_addr().expect("determine port bound to");

        debug!(
            "created UDP association {} <-> {}, {}",
            src_addr, remote_bind_addr, bypass_bind_addr
        );

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (remote_receiver, remote_sender) = remote_udp.split();
        let (bypass_receiver, bypass_sender) = bypass_udp.split();

        // LOCAL -> REMOTE task
        // Packets may be sent via proxy decided by acl rules

        tokio::spawn(Self::l2r_packet_acl(
            src_addr,
            server.clone(),
            rx,
            bypass_sender,
            remote_sender,
        ));

        // LOCAL <- REMOTE task

        let bypass_watcher =
            Self::r2l_packet_abortable(src_addr, server.clone(), sender.clone(), bypass_receiver, true);
        let remote_watcher = Self::r2l_packet_abortable(src_addr, server, sender, remote_receiver, false);
        let watchers = vec![bypass_watcher, remote_watcher];

        Ok(ProxyAssociation { tx, watchers })
    }

    async fn connect_remote(context: &Context, svr_cfg: &ServerConfig, remote_udp: &UdpSocket) -> io::Result<()> {
        match svr_cfg.addr() {
            ServerAddr::SocketAddr(ref remote_addr) => {
                let res = remote_udp.connect(remote_addr).await;
                if let Err(ref err) = res {
                    error!(
                        "UDP association UdpSocket::connect failed, addr: {}, err: {}",
                        remote_addr, err
                    );
                }
                res?;
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context, dname, *port, |addr| {
                    let res = remote_udp.connect(&addr).await;
                    if let Err(ref err) = res {
                        error!(
                            "UDP association UdpSocket::connect failed, addr: {}:{} (resolved: {}), err: {}",
                            dname, port, addr, err
                        );
                    }
                    res
                })?;
            }
        }

        Ok(())
    }

    async fn send(&mut self, target: Address, payload: Vec<u8>) {
        if let Err(..) = self.tx.send((target, payload)).await {
            // SHOULDn't HAPPEN
            unreachable!("UDP association local -> remote queue closed unexpectly");
        }
    }

    async fn l2r_packet_acl<S>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut rx: mpsc::Receiver<(Address, Vec<u8>)>,
        mut bypass_sender: SendHalf,
        mut remote_sender: SendHalf,
    ) where
        S: ServerData + Send + 'static,
    {
        let context = server.context();
        let svr_cfg = server.server_config();

        while let Some((addr, payload)) = rx.recv().await {
            // Check if addr should be bypassed
            let is_bypassed = context.check_target_bypassed(&addr).await;

            let res = if is_bypassed {
                Self::send_packet_bypassed(src_addr, context, &addr, &payload, &mut bypass_sender).await
            } else {
                Self::send_packet_proxied(src_addr, context, svr_cfg, &addr, &payload, &mut remote_sender).await
            };

            if let Err(err) = res {
                error!(
                    "failed to send packet {} -> {}, bypassed? {}, error: {}",
                    src_addr, addr, is_bypassed, err
                );
            }
        }

        debug!("UDP association {} -> .. task is closing", src_addr);
    }

    async fn l2r_packet_proxied<S>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut rx: mpsc::Receiver<(Address, Vec<u8>)>,
        mut remote_sender: SendHalf,
    ) where
        S: ServerData + Send + 'static,
    {
        let context = server.context();
        let svr_cfg = server.server_config();

        while let Some((addr, payload)) = rx.recv().await {
            let res = Self::send_packet_proxied(src_addr, context, svr_cfg, &addr, &payload, &mut remote_sender).await;

            if let Err(err) = res {
                error!(
                    "UDP association (proxied) send packet {} -> {}, error: {}",
                    src_addr, addr, err
                );
            }
        }

        debug!("UDP association (proxied) {} -> .. task is closing", src_addr);
    }

    async fn l2r_packet_bypassed<S>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut rx: mpsc::Receiver<(Address, Vec<u8>)>,
        mut remote_sender: SendHalf,
    ) where
        S: ServerData + Send + 'static,
    {
        let context = server.context();

        while let Some((addr, payload)) = rx.recv().await {
            let res = Self::send_packet_bypassed(src_addr, context, &addr, &payload, &mut remote_sender).await;

            if let Err(err) = res {
                error!(
                    "UDP association (bypassed) send packet {} -> {}, error: {}",
                    src_addr, addr, err
                );
            }
        }

        debug!("UDP association (bypassed) {} -> .. task is closing", src_addr);
    }

    async fn send_packet_proxied(
        src_addr: SocketAddr,
        context: &Context,
        svr_cfg: &ServerConfig,
        target: &Address,
        payload: &[u8],
        socket: &mut SendHalf,
    ) -> io::Result<()> {
        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::with_capacity(target.serialized_len() + payload.len());
        target.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        let (send_len, expected_len) = if let CipherCategory::None = svr_cfg.method().category() {
            let send_len = socket.send(&send_buf).await?;
            (send_len, send_buf.len())
        } else {
            let mut encrypt_buf = BytesMut::new();
            encrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

            let send_len = socket.send(&encrypt_buf).await?;
            (send_len, encrypt_buf.len())
        };

        if expected_len != send_len {
            warn!(
                "UDP association {} -> {} (proxied) {} payload truncated, expected {} bytes, but sent {} bytes",
                src_addr,
                target,
                svr_cfg.addr(),
                expected_len,
                send_len
            );
        } else {
            debug!(
                "UDP association {} -> {} (proxied) sent {} bytes",
                src_addr,
                target,
                payload.len()
            );
        }

        #[cfg(feature = "local-flow-stat")]
        {
            context.local_flow_statistic().udp().incr_tx(send_len);
        }

        Ok(())
    }

    async fn send_packet_bypassed(
        src_addr: SocketAddr,
        context: &Context,
        target: &Address,
        payload: &[u8],
        socket: &mut SendHalf,
    ) -> io::Result<()> {
        // BYPASSED, so just send it directly without any modifications

        let send_len = match *target {
            Address::SocketAddress(ref saddr) => socket.send_to(payload, saddr).await?,
            Address::DomainNameAddress(ref host, port) => {
                lookup_then!(context, host, port, |saddr| { socket.send_to(payload, &saddr).await })?.1
            }
        };

        if payload.len() != send_len {
            warn!(
                "UDP association {} -> {} (bypassed) payload truncated, expected {} bytes, but sent {} bytes",
                src_addr,
                target,
                payload.len(),
                send_len
            );
        } else {
            debug!(
                "UDP association {} -> {} (bypassed) sent {} bytes",
                src_addr,
                target,
                payload.len()
            );
        }

        Ok(())
    }

    fn r2l_packet_abortable<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
        socket: RecvHalf,
        is_bypassed: bool,
    ) -> AbortHandle
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        let relay_fut = Self::r2l_packet(src_addr, server, sender, socket);
        let (relay_task, relay_watcher) = future::abortable(relay_fut);

        tokio::spawn(async move {
            let _ = relay_task.await;

            debug!(
                "UDP association ({}) {} <- .. task is closing",
                if is_bypassed { "bypassed" } else { "proxied" },
                src_addr
            );
        });

        relay_watcher
    }

    async fn r2l_packet<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        mut sender: H,
        mut socket: RecvHalf,
    ) where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        let context = server.context();
        let svr_cfg = server.server_config();

        loop {
            match Self::recv_packet_proxied(context, svr_cfg, &mut socket).await {
                Ok((addr, data)) => {
                    debug!(
                        "UDP association {} <- .., payload length {} bytes",
                        src_addr,
                        data.len()
                    );

                    if let Err(err) = sender.send_packet(addr, data).await {
                        error!("UDP association send {} <- .., error: {}", src_addr, err);
                    }
                }
                Err(err) => {
                    error!("UDP association recv {} <- .., error: {}", src_addr, err);
                }
            }
        }
    }

    async fn recv_packet_proxied(
        context: &Context,
        svr_cfg: &ServerConfig,
        socket: &mut RecvHalf,
    ) -> io::Result<(Address, Vec<u8>)> {
        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut recv_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        let recv_n = socket.recv(&mut recv_buf).await?;

        let mut cur = if let CipherCategory::None = svr_cfg.method().category() {
            recv_buf.truncate(recv_n);
            Cursor::new(recv_buf)
        } else {
            let decrypt_buf = match decrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &recv_buf[..recv_n])? {
                None => {
                    error!("UDP packet too short, received length {}", recv_n);
                    let err = io::Error::new(io::ErrorKind::InvalidData, "packet too short");
                    return Err(err);
                }
                Some(b) => b,
            };
            Cursor::new(decrypt_buf)
        };

        // SERVER -> CLIENT protocol: ADDRESS + PAYLOAD
        // FIXME: Address is ignored. Maybe useful in the future if we uses one common UdpSocket for communicate with remote server
        let addr = Address::read_from(&mut cur).await?;

        let mut payload = Vec::with_capacity(recv_n - cur.position() as usize);
        cur.read_to_end(&mut payload)?;

        #[cfg(feature = "local-flow-stat")]
        {
            context.local_flow_statistic().udp().incr_rx(recv_n);
        }

        Ok((addr, payload))
    }
}

struct AssociationManagerInner<K, A> {
    map: Arc<Mutex<LruCache<K, A>>>,
    watcher: AbortHandle,
}

impl<K, A> Drop for AssociationManagerInner<K, A> {
    fn drop(&mut self) {
        self.watcher.abort()
    }
}

pub struct AssociationManager<K, A> {
    inner: Arc<AssociationManagerInner<K, A>>,
}

impl<K, A> Clone for AssociationManager<K, A> {
    fn clone(&self) -> Self {
        AssociationManager {
            inner: self.inner.clone(),
        }
    }
}

impl<K, A> AssociationManager<K, A>
where
    K: Ord + Clone + Send + 'static,
    A: Send + 'static,
{
    /// Create a new AssociationManager based on Config
    pub fn new(config: &Config) -> AssociationManager<K, A> {
        let timeout = config.udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        // TODO: Set default capacity by getrlimit #262
        // Associations are only eliminated by expire time by default
        // So it may exhaust all available file descriptors
        let assoc_map = if let Some(max_assoc) = config.udp_max_associations {
            LruCache::with_expiry_duration_and_capacity(timeout, max_assoc)
        } else {
            LruCache::with_expiry_duration(timeout)
        };

        let map = Arc::new(Mutex::new(assoc_map));

        // Create a task for releasing timed out association
        let map2 = map.clone();
        let (release_task, watcher) = future::abortable(async move {
            let mut interval = time::interval(timeout);
            loop {
                interval.tick().await;

                let mut m = map2.lock().await;
                // Cleanup expired association
                // Do not consume this iterator, it will updates expire time of items that traversed
                let _ = m.iter();

                if m.len() > 0 {
                    debug!("UDP associations totally kept {}", m.len());
                }
            }
        });

        tokio::spawn(release_task);

        AssociationManager {
            inner: Arc::new(AssociationManagerInner { map, watcher }),
        }
    }

    /// Try to reset ProxyAssociation's last used time by key
    ///
    /// Return true if ProxyAssociation is still exist
    #[inline]
    pub async fn keep_alive(&self, key: &K) -> bool {
        let mut assoc = self.inner.map.lock().await;
        assoc.get(key).is_some()
    }
}

impl<K> AssociationManager<K, ProxyAssociation>
where
    K: Ord + Clone + Send + 'static,
{
    /// Send a packet to target address
    ///
    /// Create a new association by `create_fut` if association doesn't exist
    pub async fn send_packet<CFut>(&self, key: K, target: Address, payload: Vec<u8>, create_fut: CFut) -> io::Result<()>
    where
        CFut: Future<Output = io::Result<ProxyAssociation>>,
    {
        let mut assoc_map = self.inner.map.lock().await;
        let assoc = match assoc_map.entry(key) {
            Entry::Occupied(oc) => oc.into_mut(),
            Entry::Vacant(vc) => vc.insert(create_fut.await?),
        };

        // FIXME: Lock is still kept for a mutable reference
        // Send to local -> remote task
        assoc.send(target, payload).await;

        Ok(())
    }
}

/// Association manager for local
pub type ProxyAssociationManager<K> = AssociationManager<K, ProxyAssociation>;

// Represent a UDP association in server
pub struct ServerAssociation {
    // local -> remote Queue
    // Drops tx, will close local -> remote task
    tx: mpsc::Sender<Vec<u8>>,

    // local <- remote task life watcher
    watcher: AbortHandle,
}

impl Drop for ServerAssociation {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

impl ServerAssociation {
    /// Create an association with addr
    pub async fn associate(
        context: SharedContext,
        svr_idx: usize,
        src_addr: SocketAddr,
        mut response_tx: mpsc::Sender<(SocketAddr, BytesMut)>,
    ) -> io::Result<ServerAssociation> {
        // Create a socket for receiving packets
        let local_addr = match context.config().local_addr {
            None => {
                // Let system allocate an address for us
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
            }
            Some(ref addr) => {
                // Uses configured local address
                addr.bind_addr(&context).await?
            }
        };
        let remote_udp = create_udp_socket(&local_addr).await?;

        let local_addr = remote_udp.local_addr().expect("could not determine port bound to");
        debug!("created UDP Association for {} from {}", src_addr, local_addr);

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        // Splits socket into sender and receiver
        let (mut receiver, mut sender) = remote_udp.split();

        let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        // local -> remote
        {
            let context = context.clone();
            tokio::spawn(async move {
                let svr_cfg = context.server_config(svr_idx);

                while let Some(pkt) = rx.recv().await {
                    // pkt is already a raw packet, so just send it
                    if let Err(err) =
                        ServerAssociation::relay_l2r(&context, src_addr, &mut sender, pkt, timeout, svr_cfg).await
                    {
                        error!("failed to relay packet, {} -> ..., error: {}", src_addr, err);

                        // FIXME: Ignore? Or how to deal with it?
                    }
                }

                debug!("UDP ASSOCIATE {} -> .. finished", src_addr);
            });
        }

        let (r2l_task, close_flag) = future::abortable(async move {
            let svr_cfg = context.server_config(svr_idx);

            loop {
                // Read and send back to source
                match ServerAssociation::relay_r2l(&context, src_addr, &mut receiver, &mut response_tx, svr_cfg).await {
                    Ok(..) => {}
                    Err(err) => {
                        error!("failed to receive packet, {} <- .., error: {}", src_addr, err);

                        // FIXME: Don't break, or if you can find a way to drop the ServerAssociation
                        // break;
                    }
                }
            }
        });

        // local <- remote
        tokio::spawn(async move {
            let _ = r2l_task.await;

            debug!("UDP ASSOCIATE {} <- .. finished", src_addr);
        });

        Ok(ServerAssociation {
            tx,
            watcher: close_flag,
        })
    }

    /// Relay packets from local to remote
    async fn relay_l2r(
        context: &Context,
        src: SocketAddr,
        remote_udp: &mut SendHalf,
        pkt: Vec<u8>,
        timeout: Duration,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        // First of all, decrypt payload CLIENT -> SERVER
        let mut cur = if let CipherCategory::None = svr_cfg.method().category() {
            Cursor::new(pkt)
        } else {
            let decrypted_pkt = match decrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &pkt) {
                Ok(Some(pkt)) => pkt,
                Ok(None) => {
                    error!("failed to decrypt pkt in UDP relay, packet too short");
                    let err = io::Error::new(io::ErrorKind::InvalidData, "packet too short");
                    return Err(err);
                }
                Err(err) => {
                    error!("failed to decrypt pkt in UDP relay: {}", err);
                    let err = io::Error::new(io::ErrorKind::InvalidData, "decrypt failed");
                    return Err(err);
                }
            };

            Cursor::new(decrypted_pkt)
        };

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let addr = Address::read_from(&mut cur).await?;

        if context.check_outbound_blocked(&addr).await {
            warn!("{} -> outbound {} is blocked by ACL rules", src, addr);
            return Ok(());
        }

        // Take out internal buffer for optimizing one byte copy
        let header_len = cur.position() as usize;
        let decrypted_pkt = cur.into_inner();
        let body = &decrypted_pkt[header_len..];

        let send_len = match addr {
            Address::SocketAddress(ref remote_addr) => {
                debug!(
                    "UDP ASSOCIATE {} -> {} ({}), payload length {} bytes",
                    src,
                    addr,
                    remote_addr,
                    body.len()
                );
                try_timeout(remote_udp.send_to(body, remote_addr), Some(timeout)).await?
            }
            Address::DomainNameAddress(ref dname, port) => lookup_then!(context, dname, port, |remote_addr| {
                match try_timeout(remote_udp.send_to(body, &remote_addr), Some(timeout)).await {
                    Ok(l) => {
                        debug!(
                            "UDP ASSOCIATE {} -> {} ({}), payload length {} bytes",
                            src,
                            addr,
                            remote_addr,
                            body.len()
                        );
                        Ok(l)
                    }
                    Err(err) => {
                        error!(
                            "UDP ASSOCIATE {} -> {} ({}), payload length {} bytes",
                            src,
                            addr,
                            remote_addr,
                            body.len()
                        );
                        Err(err)
                    }
                }
            })
            .map(|(_, l)| l)?,
        };

        assert_eq!(body.len(), send_len);

        Ok(())
    }

    /// Relay packets from remote to local
    async fn relay_r2l(
        context: &Context,
        src_addr: SocketAddr,
        remote_udp: &mut RecvHalf,
        response_tx: &mut mpsc::Sender<(SocketAddr, BytesMut)>,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut remote_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (remote_recv_len, remote_addr) = remote_udp.recv_from(&mut remote_buf).await?;

        debug!(
            "UDP ASSOCIATE {} <- {}, payload length {} bytes",
            src_addr, remote_addr, remote_recv_len
        );

        // FIXME: The Address should be the Address that client sent
        let addr = Address::SocketAddress(remote_addr);

        // CLIENT <- SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = BytesMut::with_capacity(addr.serialized_len() + remote_recv_len);
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(&remote_buf[..remote_recv_len]);

        if let CipherCategory::None = svr_cfg.method().category() {
            // Send back to src_addr
            if let Err(err) = response_tx.send((src_addr, send_buf)).await {
                error!("failed to send packet into response channel, error: {}", err);

                // FIXME: What to do? Ignore?
            }
        } else {
            let mut encrypt_buf = BytesMut::new();
            encrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

            // Send back to src_addr
            if let Err(err) = response_tx.send((src_addr, encrypt_buf)).await {
                error!("failed to send packet into response channel, error: {}", err);

                // FIXME: What to do? Ignore?
            }
        }

        Ok(())
    }

    // Send packet to remote
    //
    // Return `Err` if receiver have been closed
    async fn send(&mut self, pkt: Vec<u8>) {
        if let Err(..) = self.tx.send(pkt).await {
            // SHOULDn't HAPPEN
            unreachable!("UDP Association local -> remote Queue closed unexpectly");
        }
    }
}

impl<K> AssociationManager<K, ServerAssociation>
where
    K: Ord + Clone + Send + 'static,
{
    /// Send a packet to target address
    ///
    /// Create a new association by `create_fut` if association doesn't exist
    pub async fn send_packet<CFut>(&self, key: K, payload: Vec<u8>, create_fut: CFut) -> io::Result<()>
    where
        CFut: Future<Output = io::Result<ServerAssociation>>,
    {
        let mut assoc_map = self.inner.map.lock().await;
        let assoc = match assoc_map.entry(key) {
            Entry::Occupied(oc) => oc.into_mut(),
            Entry::Vacant(vc) => vc.insert(create_fut.await?),
        };

        // FIXME: Lock is still kept for a mutable reference
        // Send to local -> remote task
        assoc.send(payload).await;

        Ok(())
    }
}

/// Association manager for server
pub type ServerAssociationManager<K> = AssociationManager<K, ServerAssociation>;
