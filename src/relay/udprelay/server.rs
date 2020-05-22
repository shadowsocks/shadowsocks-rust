//! UDP relay proxy server

use std::{
    io::{self, Cursor},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use futures::{future, future::AbortHandle, stream::FuturesUnordered, StreamExt};
use log::{debug, error, info, trace, warn};
use lru_time_cache::{Entry, LruCache};
use tokio::{
    self,
    net::udp::{RecvHalf, SendHalf},
    sync::{mpsc, Mutex},
};

use crate::{
    config::ServerConfig,
    context::{Context, SharedContext},
    relay::{
        flow::{SharedMultiServerFlowStatistic, SharedServerFlowStatistic},
        socks5::Address,
        sys::create_udp_socket,
        utils::try_timeout,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

// Represent a UDP association
struct UdpAssociation {
    // local -> remote Queue
    // Drops tx, will close local -> remote task
    tx: mpsc::Sender<Vec<u8>>,

    // local <- remote task life watcher
    watcher: AbortHandle,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

impl UdpAssociation {
    /// Create an association with addr
    async fn associate(
        context: SharedContext,
        svr_idx: usize,
        src_addr: SocketAddr,
        mut response_tx: mpsc::Sender<(SocketAddr, BytesMut)>,
    ) -> io::Result<UdpAssociation> {
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
                        UdpAssociation::relay_l2r(&context, src_addr, &mut sender, &pkt[..], timeout, svr_cfg).await
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
                match UdpAssociation::relay_r2l(&context, src_addr, &mut receiver, &mut response_tx, svr_cfg).await {
                    Ok(..) => {}
                    Err(err) => {
                        error!("failed to receive packet, {} <- .., error: {}", src_addr, err);

                        // FIXME: Don't break, or if you can find a way to drop the UdpAssociation
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
        pkt: &[u8],
        timeout: Duration,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        // First of all, decrypt payload CLIENT -> SERVER
        let decrypted_pkt = match decrypt_payload(context, svr_cfg.method(), svr_cfg.key(), pkt) {
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

        debug!("UDP ASSOCIATE {} <-> {} establishing", src, addr);

        if context.check_outbound_blocked(&addr) {
            warn!("outbound {} is blocked by ACL rules", addr);
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
            Address::DomainNameAddress(ref dname, port) => lookup_outbound_then!(context, dname, port, |remote_addr| {
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
        let mut send_buf = Vec::new();
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(&remote_buf[..remote_recv_len]);

        let mut encrypt_buf = BytesMut::new();
        encrypt_payload(context, svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

        // Send back to src_addr
        if let Err(err) = response_tx.send((src_addr, encrypt_buf)).await {
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

fn serialize(saddr: &SocketAddr) -> [u8; 18] {
    let mut result = [0; 18];
    result[..16].copy_from_slice(&match saddr.ip() {
        IpAddr::V4(ref ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ref ip) => ip.octets(),
    });
    result[16..].copy_from_slice(&saddr.port().to_ne_bytes());
    result
}

async fn listen(context: SharedContext, flow_stat: SharedServerFlowStatistic, svr_idx: usize) -> io::Result<()> {
    let svr_cfg = context.server_config(svr_idx);
    let listen_addr = svr_cfg.addr().bind_addr(&context).await?;

    let listener = create_udp_socket(&listen_addr).await?;
    let local_addr = listener.local_addr().expect("determine port bound to");
    info!("shadowsocks UDP listening on {}", local_addr);

    let (mut r, mut w) = listener.split();

    // NOTE: Associations are only eliminated by expire time by default
    // So it may exhaust all available file descriptors
    let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);
    let assoc_map = if let Some(max_assoc) = context.config().udp_max_associations {
        LruCache::with_expiry_duration_and_capacity(timeout, max_assoc)
    } else {
        LruCache::with_expiry_duration(timeout)
    };
    let assoc_map = Arc::new(Mutex::new(assoc_map));

    // FIXME: Channel size 1024?
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, BytesMut)>(1024);

    {
        // Tokio task for sending data back to clients

        let assoc_map = assoc_map.clone();
        let flow_stat = flow_stat.clone();

        tokio::spawn(async move {
            while let Some((src, pkt)) = rx.recv().await {
                let cache_key = serialize(&src);
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

                flow_stat.udp().incr_tx(pkt.len() as u64);
            }

            // FIXME: How to stop the outer listener Future?
        });
    }

    let mut pkt_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src) = r.recv_from(&mut pkt_buf).await?;

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let pkt = &pkt_buf[..recv_len];

        trace!("received UDP packet from {}, length {} bytes", src, recv_len);
        flow_stat.udp().incr_rx(pkt.len() as u64);

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

        // Check ACL
        if context.check_client_blocked(&src) {
            warn!("client {} is blocked by ACL rules", src);
            continue;
        }

        // Check or (re)create an association
        {
            // Locks the whole association map
            let mut assoc_map = assoc_map.lock().await;

            // Get or create an association
            let assoc = match assoc_map.entry(serialize(&src)) {
                Entry::Occupied(oc) => oc.into_mut(),
                Entry::Vacant(vc) => vc.insert(
                    UdpAssociation::associate(context.clone(), svr_idx, src, tx.clone())
                        .await
                        .expect("create udp association"),
                ),
            };

            // FIXME: Lock is still kept for a mutable reference
            // Send to local -> remote task
            assoc.send(pkt.to_vec()).await;
        }
    }
}

/// Starts a UDP relay server
pub async fn run(context: SharedContext, flow_stat: SharedMultiServerFlowStatistic) -> io::Result<()> {
    let vec_fut = FuturesUnordered::new();

    for (svr_idx, svr_cfg) in context.config().server.iter().enumerate() {
        let context = context.clone();
        let flow_stat = flow_stat
            .get(svr_cfg.addr().port())
            .expect("port not existed in multi-server flow statistic")
            .clone();

        let svr_fut = listen(context, flow_stat, svr_idx);
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
