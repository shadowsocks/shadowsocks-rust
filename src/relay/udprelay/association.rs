//! UDP Association
//!
//! Working like a NAT proxy

#![allow(dead_code)]

use std::{
    future::Future,
    io::{self, Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::future::{self, AbortHandle};
use log::{debug, error, warn};
use lru_time_cache::{Entry, LruCache};
use tokio::{
    self,
    net::udp::{RecvHalf, SendHalf},
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    config::{Config, ServerAddr, ServerConfig},
    context::Context,
    relay::{
        loadbalancing::server::{ServerData, SharedServerStatistic},
        socks5::Address,
        sys::create_udp_socket_with_context,
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

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (remote_receiver, remote_sender) = remote_udp.split();

        // LOCAL -> REMOTE task
        // All packets will be sent directly to proxy
        tokio::spawn(Self::l2r_packet_proxied(src_addr, server.clone(), rx, remote_sender));

        // REMOTE <- LOCAL task
        let remote_watcher = Self::r2l_packet_abortable(src_addr, server, sender, remote_receiver);
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
        let remote_watcher = Self::r2l_packet_abortable(src_addr, server, sender, remote_receiver);
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
        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        let remote_udp = create_udp_socket_with_context(&local_addr, server.context()).await?;
        let remote_bind_addr = remote_udp.local_addr().expect("determine port bound to");

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

        let bypass_watcher = Self::r2l_packet_abortable(src_addr, server.clone(), sender.clone(), bypass_receiver);
        let remote_watcher = Self::r2l_packet_abortable(src_addr, server, sender, remote_receiver);
        let watchers = vec![bypass_watcher, remote_watcher];

        Ok(ProxyAssociation { tx, watchers })
    }

    pub async fn send(&mut self, target: Address, payload: Vec<u8>) {
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
        let mut send_buf = Vec::new();
        target.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        let mut encrypt_buf = BytesMut::new();
        encrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

        let send_len = match svr_cfg.addr() {
            ServerAddr::SocketAddr(ref remote_addr) => socket.send_to(&encrypt_buf[..], remote_addr).await?,
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context, dname, *port, |addr| {
                    socket.send_to(&encrypt_buf[..], &addr).await
                })?
                .1
            }
        };

        if encrypt_buf.len() != send_len {
            warn!(
                "UDP association {} -> {} via proxy {} payload truncated, expected {} bytes, but sent {} bytes",
                src_addr,
                target,
                svr_cfg.addr(),
                encrypt_buf.len(),
                send_len
            );
        }

        #[cfg(feature = "local-flow-stat")]
        {
            context.local_flow_statistic().udp().incr_tx(send_len as u64);
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
                "UDP association {} -> {} payload truncated, expected {} bytes, but sent {} bytes",
                src_addr,
                target,
                payload.len(),
                send_len
            );
        }

        Ok(())
    }

    fn r2l_packet_abortable<S, H>(
        src_addr: SocketAddr,
        server: SharedServerStatistic<S>,
        sender: H,
        socket: RecvHalf,
    ) -> AbortHandle
    where
        S: ServerData + Send + 'static,
        H: ProxySend + Send + 'static,
    {
        let relay_fut = Self::r2l_packet(src_addr, server, sender, socket);
        let (relay_task, relay_watcher) = future::abortable(relay_fut);

        tokio::spawn(async move {
            let _ = relay_task.await;

            debug!("UDP association {} <- .. task is closing", src_addr);
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

        let (recv_n, _) = socket.recv_from(&mut recv_buf).await?;

        let decrypt_buf = match decrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &recv_buf[..recv_n])? {
            None => {
                error!("UDP packet too short, received length {}", recv_n);
                let err = io::Error::new(io::ErrorKind::InvalidData, "packet too short");
                return Err(err);
            }
            Some(b) => b,
        };
        // SERVER -> CLIENT protocol: ADDRESS + PAYLOAD
        let mut cur = Cursor::new(decrypt_buf);
        // FIXME: Address is ignored. Maybe useful in the future if we uses one common UdpSocket for communicate with remote server
        let addr = Address::read_from(&mut cur).await?;

        let mut payload = Vec::new();
        cur.read_to_end(&mut payload)?;

        #[cfg(feature = "local-flow-stat")]
        {
            context.local_flow_statistic().udp().incr_rx(recv_n as u64);
        }

        Ok((addr, payload))
    }
}

#[derive(Clone)]
pub struct ProxyAssociationManager<K> {
    map: Arc<Mutex<LruCache<K, ProxyAssociation>>>,
    watcher: AbortHandle,
}

impl<K> Drop for ProxyAssociationManager<K> {
    fn drop(&mut self) {
        self.watcher.abort()
    }
}

impl<K> ProxyAssociationManager<K>
where
    K: Ord + Clone + Send + 'static,
{
    /// Create a new ProxyAssociationManager based on Config
    pub fn new(config: &Config) -> ProxyAssociationManager<K> {
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
            }
        });

        tokio::spawn(release_task);

        ProxyAssociationManager { map, watcher }
    }

    /// Try to reset ProxyAssociation's last used time by key
    ///
    /// Return true if ProxyAssociation is still exist
    pub async fn keep_alive(&self, key: &K) -> bool {
        let mut assoc = self.map.lock().await;
        assoc.get(key).is_some()
    }

    /// Send a packet to target address
    ///
    /// Create a new association by `create_fut` if association doesn't exist
    pub async fn send_packet<F>(&self, key: K, target: Address, pkt: Vec<u8>, create_fut: F) -> io::Result<()>
    where
        F: Future<Output = io::Result<ProxyAssociation>>,
    {
        let mut assoc_map = self.map.lock().await;
        let assoc = match assoc_map.entry(key) {
            Entry::Occupied(oc) => oc.into_mut(),
            Entry::Vacant(vc) => vc.insert(create_fut.await?),
        };

        // FIXME: Lock is still kept for a mutable reference
        // Send to local -> remote task
        assoc.send(target, pkt).await;

        Ok(())
    }
}
