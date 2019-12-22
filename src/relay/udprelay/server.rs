//! UDP relay proxy server

use std::{
    io::{self, Cursor},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::BytesMut;
use futures::{self, stream::FuturesUnordered, StreamExt};
use log::{debug, error, info, trace};
use lru_time_cache::{Entry, LruCache};
use tokio::{
    self,
    net::udp::{RecvHalf, SendHalf},
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    config::ServerConfig,
    context::{Context, SharedContext},
    relay::{socks5::Address, utils::try_timeout},
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    utils::create_socket,
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

// Represent a UDP association
struct UdpAssociation {
    tx: mpsc::Sender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        // 1. Drops tx, will close local -> remote task
        // 2. Drops closed, will close local <- remote task
        self.closed.store(true, Ordering::Release);
    }
}

impl UdpAssociation {
    /// Create an association with addr
    async fn associate(
        context: SharedContext,
        svr_cfg: Arc<ServerConfig>,
        src_addr: SocketAddr,
        mut response_tx: mpsc::Sender<(SocketAddr, BytesMut)>,
    ) -> io::Result<UdpAssociation> {
        debug!("created UDP Association for {}", src_addr);

        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let remote_udp = create_socket(&local_addr).await?;

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        let close_flag = Arc::new(AtomicBool::new(false));

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
                    error!("failed to relay packet, {} -> ..., error: {}", src_addr, err);

                    // FIXME: Ignore? Or how to deal with it?
                }
            }

            debug!("UDP ASSOCIATE {} -> .. finished", src_addr);
        });

        // local <- remote
        let closed = close_flag.clone();
        tokio::spawn(async move {
            while !closed.load(Ordering::Acquire) {
                use std::io::ErrorKind;

                // Read and send back to source
                match UdpAssociation::relay_r2l(src_addr, &mut receiver, timeout, &mut response_tx, &*svr_cfg).await {
                    Ok(..) => {}
                    Err(ref err) if err.kind() == ErrorKind::TimedOut => {
                        trace!("receive packet timeout, {} <- ...", src_addr);
                    }
                    Err(err) => {
                        error!("railed to receive packet, {} <- .., error: {}", src_addr, err);

                        // FIXME: Don't break, or if you can find a way to drop the UdpAssociation
                        // break;
                    }
                }
            }

            debug!("UDP ASSOCIATE {} <- .. finished", src_addr);
        });

        Ok(UdpAssociation { tx, closed: close_flag })
    }

    /// Relay packets from local to remote
    #[cfg_attr(not(feature = "trust-dns"), allow(unused_variables))]
    async fn relay_l2r(
        context: &Context,
        src: SocketAddr,
        remote_udp: &mut SendHalf,
        pkt: &[u8],
        timeout: Duration,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        // First of all, decrypt payload CLIENT -> SERVER
        let decrypted_pkt = match decrypt_payload(svr_cfg.method(), svr_cfg.key(), pkt) {
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

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut cur = Cursor::new(decrypted_pkt);

        let addr = Address::read_from(&mut cur).await?;

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
            #[cfg(feature = "trust-dns")]
            Address::DomainNameAddress(ref dname, port) => {
                use crate::relay::dns_resolver::resolve;

                let vec_ipaddr = resolve(context, dname, port, false).await?;
                assert!(!vec_ipaddr.is_empty());

                let remote_addr = &vec_ipaddr[0];

                debug!(
                    "UDP ASSOCIATE {} -> {} ({}), payload length {} bytes",
                    src,
                    addr,
                    remote_addr,
                    body.len()
                );

                try_timeout(remote_udp.send_to(body, remote_addr), Some(timeout)).await?
            }
            #[cfg(not(feature = "trust-dns"))]
            Address::DomainNameAddress(ref dname, port) => {
                debug!("UDP ASSOCIATE {} -> {}, payload length {} bytes", src, addr, body.len());

                // try_timeout(remote_udp.send_to(body, (dname.as_str(), port)), Some(timeout)).await?
                unimplemented!(
                    "tokio's UdpSocket SendHalf doesn't support ToSocketAddrs, {}:{}",
                    dname,
                    port
                );
            }
        };

        assert_eq!(body.len(), send_len);

        Ok(())
    }

    /// Relay packets from remote to local
    async fn relay_r2l(
        src_addr: SocketAddr,
        remote_udp: &mut RecvHalf,
        timeout: Duration,
        response_tx: &mut mpsc::Sender<(SocketAddr, BytesMut)>,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut remote_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (remote_recv_len, remote_addr) = try_timeout(remote_udp.recv_from(&mut remote_buf), Some(timeout)).await?;

        debug!(
            "UDP ASSOCIATE {} <- {}, payload length {} bytes",
            src_addr, remote_addr, remote_recv_len
        );

        // FIXME: The Address should be the Address that client sent
        let addr = Address::SocketAddress(remote_addr);

        // CLIENT <- SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::new();
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(&remote_buf[..remote_recv_len]);

        let mut encrypt_buf = BytesMut::new();
        encrypt_payload(svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

        // Send back to src_addr
        if let Err(err) = response_tx.send((src_addr, encrypt_buf)).await {
            error!("failed to send packet into response channel, error: {}", err);

            // FIXME: What to do? Ignore?
        }

        Ok(())
    }

    async fn send(&mut self, pkt: &[u8]) -> bool {
        match self.tx.send(pkt.to_vec()).await {
            Ok(..) => true,
            Err(err) => {
                error!("failed to send packet, error: {}", err);
                false
            }
        }
    }
}

async fn listen(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> io::Result<()> {
    let listen_addr = *svr_cfg.addr().listen_addr();
    info!("ShadowSocks UDP listening on {}", listen_addr);

    let listener = create_socket(&listen_addr).await?;
    let (mut r, mut w) = listener.split();

    // NOTE: Associations are only eliminated by expire time
    // So it may exhaust all available file descriptors
    let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);
    let assoc_map = Arc::new(Mutex::new(LruCache::with_expiry_duration(timeout)));
    let assoc_map_cloned = assoc_map.clone();

    // FIXME: Channel size 1024?
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, BytesMut)>(1024);
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

    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

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
        let pkt = &pkt_buf[..recv_len];

        trace!("received UDP packet from {}, length {} bytes", src, recv_len);

        if recv_len == 0 {
            // Interestingly some clients may send a empty packet to server
            continue;
        }

        // Check or (re)create an association
        loop {
            let mut assoc_map = assoc_map.lock().await;

            let retry = {
                let assoc = match assoc_map.entry(src.to_string()) {
                    Entry::Occupied(oc) => oc.into_mut(),
                    Entry::Vacant(vc) => vc.insert(
                        UdpAssociation::associate(context.clone(), svr_cfg.clone(), src, tx.clone())
                            .await
                            .expect("Failed to create udp association"),
                    ),
                };

                !assoc.send(pkt).await
            };

            if retry {
                assoc_map.remove(&src.to_string());
            } else {
                break;
            }
        }
    }
}

/// Starts a UDP relay server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let vec_fut = FuturesUnordered::new();

    for svr in &context.config().server {
        let svr_cfg = Arc::new(svr.clone());

        let svr_fut = listen(context.clone(), svr_cfg);
        vec_fut.push(svr_fut);
    }

    match vec_fut.into_future().await.0 {
        Some(res) => {
            error!("one of UDP servers exited unexpectly, result: {:?}", res);
            let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
            Err(err)
        }
        None => unreachable!(),
    }
}
