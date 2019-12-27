//! UDP relay local server

use std::{
    io::{self, Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use futures::{future, FutureExt};
use log::{debug, error, info, trace};
use lru_time_cache::{Entry, LruCache};
use tokio::{
    self,
    net::udp::{RecvHalf, SendHalf},
    sync::{mpsc, oneshot, Mutex},
    time,
};

use crate::{
    config::{ServerAddr, ServerConfig},
    context::{Context, SharedContext},
    relay::{
        loadbalancing::server::{ping, LoadBalancer, PingBalancer},
        socks5::Address,
        utils::try_timeout,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    utils::create_socket,
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

// Drop the oneshot::Sender<()> will trigger local <- remote task to finish
struct UdpAssociationWatcher(oneshot::Sender<()>);

// Represent a UDP association
#[derive(Clone)]
struct UdpAssociation {
    // local -> remote Queue
    // Drops tx, will close local -> remote task
    tx: mpsc::Sender<Vec<u8>>,

    // local <- remote task life watcher
    watcher: Arc<UdpAssociationWatcher>,
}

impl UdpAssociation {
    /// Create an association with addr
    async fn associate(
        context: SharedContext,
        svr_cfg: Arc<ServerConfig>,
        src_addr: SocketAddr,
        mut response_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    ) -> io::Result<UdpAssociation> {
        debug!("Created UDP Association for {}", src_addr);

        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let remote_udp = create_socket(&local_addr).await?;

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        // Create a watcher for local <- remote task
        let (watcher_tx, watcher_rx) = oneshot::channel::<()>();

        let close_flag = Arc::new(UdpAssociationWatcher(watcher_tx));

        // Splits socket into sender and receiver
        let (mut receiver, mut sender) = remote_udp.split();

        let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        // local -> remote
        let c_svr_cfg = svr_cfg.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                // pkt is already a raw packet, so just send it
                if let Err(err) =
                    UdpAssociation::relay_l2r(&*context, src_addr, &mut sender, &pkt[..], timeout, &*c_svr_cfg).await
                {
                    error!("failed to send packet {} -> ..., error: {}", src_addr, err);

                    // FIXME: Ignore? Or how to deal with it?
                }
            }

            debug!("UDP TUNNEL {} -> .. finished", src_addr);
        });

        // local <- remote
        tokio::spawn(async move {
            let transfer_fut = async move {
                loop {
                    // Read and send back to source
                    match UdpAssociation::relay_r2l(src_addr, &mut receiver, &mut response_tx, &*svr_cfg).await {
                        Ok(..) => {}
                        Err(err) => {
                            error!("failed to receive packet, {} <- .., error: {}", src_addr, err);

                            // FIXME: Don't break, or if you can find a way to drop the UdpAssociation
                            // break;
                        }
                    }
                }
            };

            // Resolved only if watcher_rx resolved
            let _ = future::select(transfer_fut.boxed(), watcher_rx.boxed()).await;

            debug!("UDP TUNNEL {} <- .. finished", src_addr);
        });

        Ok(UdpAssociation {
            tx,
            watcher: close_flag,
        })
    }

    /// Relay packets from local to remote
    async fn relay_l2r(
        context: &Context,
        src: SocketAddr,
        remote_udp: &mut SendHalf,
        payload: &[u8],
        timeout: Duration,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        let addr = context.config().forward.as_ref().unwrap();

        debug!("UDP TUNNEL {} -> {}, payload length {} bytes", src, addr, payload.len());

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::new();
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        let mut encrypt_buf = BytesMut::new();
        encrypt_payload(svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

        let send_len = match svr_cfg.addr() {
            ServerAddr::SocketAddr(ref remote_addr) => {
                try_timeout(remote_udp.send_to(&encrypt_buf[..], remote_addr), Some(timeout)).await?
            }
            #[cfg(feature = "trust-dns")]
            ServerAddr::DomainName(ref dname, port) => {
                use crate::relay::dns_resolver::resolve;

                let vec_ipaddr = resolve(context, dname, *port, false).await?;
                assert!(!vec_ipaddr.is_empty());

                try_timeout(remote_udp.send_to(&encrypt_buf[..], &vec_ipaddr[0]), Some(timeout)).await?
            }
            #[cfg(not(feature = "trust-dns"))]
            ServerAddr::DomainName(ref dname, port) => {
                // try_timeout(remote_udp.send_to(&encrypt_buf[..], (dname.as_str(), port)), Some(timeout)).await?
                unimplemented!(
                    "tokio's UdpSocket SendHalf doesn't support ToSocketAddrs, {}:{}",
                    dname,
                    port
                );
            }
        };

        assert_eq!(encrypt_buf.len(), send_len);

        Ok(())
    }

    /// Relay packets from remote to local
    async fn relay_r2l(
        src_addr: SocketAddr,
        remote_udp: &mut RecvHalf,
        response_tx: &mut mpsc::Sender<(SocketAddr, Vec<u8>)>,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut recv_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        let (recv_n, remote_addr) = remote_udp.recv_from(&mut recv_buf).await?;

        let decrypt_buf = match decrypt_payload(svr_cfg.method(), svr_cfg.key(), &recv_buf[..recv_n])? {
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
        let _ = Address::read_from(&mut cur).await?;

        let mut payload = Vec::new();
        cur.read_to_end(&mut payload)?;

        debug!(
            "UDP TUNNEL {} <- {}, payload length {} bytes",
            src_addr,
            remote_addr,
            payload.len()
        );

        // Send back to src_addr
        if let Err(err) = response_tx.send((src_addr, payload)).await {
            error!("failed to send packet into response channel, error: {}", err);

            // FIXME: What to do? Ignore?
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

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = *context.config().local.as_ref().unwrap();

    let l = create_socket(&local_addr).await?;

    let mut balancer = PingBalancer::new(context.clone(), ping::ServerType::Udp).await;

    let (mut r, mut w) = l.split();

    info!(
        "ShadowSocks UDP Tunnel listening on {}, forward to {}",
        local_addr,
        context.config().forward.as_ref().unwrap()
    );

    // NOTE: Associations are only eliminated by expire time
    // So it may exhaust all available file descriptors
    let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);
    let assoc_map = Arc::new(Mutex::new(LruCache::with_expiry_duration(timeout)));
    let assoc_map_cloned = assoc_map.clone();

    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    // FIXME: Channel size 1024?
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
    tokio::spawn(async move {
        let assoc_map = assoc_map_cloned;

        while let Some((src, pkt)) = rx.recv().await {
            let cache_key = src.to_string();
            {
                let mut amap = assoc_map.lock().await;

                // Check or update expire time
                if amap.get(&cache_key).is_none() {
                    debug!(
                        "UDP association {} <-> ... is already expired, throwing away packet {} bytes",
                        src,
                        pkt.len()
                    );
                    continue;
                }
            }

            if let Err(err) = w.send_to(&pkt, &src).await {
                error!("UDP packet send failed, err: {:?}", err);
                break;
            }
        }

        // FIXME: How to stop the outer listener Future?
    });

    loop {
        let (recv_len, src) = match time::timeout(timeout, r.recv_from(&mut pkt_buf)).await {
            Ok(r) => r?,
            Err(..) => {
                // Cleanup expired association
                // Do not consume this iterator, it will updates expire time of items that traversed
                let mut assoc_map = assoc_map.lock().await;
                let _ = assoc_map.iter();
                continue;
            }
        };

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        // Copy bytes, because udp_associate runs in another tokio Task
        let pkt = &pkt_buf[..recv_len];

        trace!("received UDP packet from {}, length {} bytes", src, recv_len);

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

        // Check or (re)create an association
        let mut assoc = {
            // Locks the whole association map
            let mut assoc_map = assoc_map.lock().await;

            // Get or create an association
            let assoc = match assoc_map.entry(src.to_string()) {
                Entry::Occupied(oc) => oc.into_mut(),
                Entry::Vacant(vc) => {
                    // Pick a server
                    let svr_cfg = balancer.pick_server();

                    vc.insert(
                        UdpAssociation::associate(context.clone(), svr_cfg.clone(), src, tx.clone())
                            .await
                            .expect("Failed to create udp association"),
                    )
                }
            };

            // Clone the handle and release the lock.
            // Make sure we keep the critical section small
            assoc.clone()
        };

        // Send to local -> remote task
        assoc.send(pkt.to_vec()).await;
    }
}
