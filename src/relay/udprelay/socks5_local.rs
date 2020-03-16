//! UDP relay local server

use std::{
    io::{self, Cursor, ErrorKind, Read},
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, trace};
use lru_time_cache::{Entry, LruCache};
use tokio::{
    self,
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        socks5::{Address, UdpAssociateHeader},
        sys::create_udp_socket,
    },
};

use super::{
    association::{ProxyAssociation, ProxySend},
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

#[derive(Clone)]
struct ProxyHandler {
    src_addr: SocketAddr,
    response_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

#[async_trait]
impl ProxySend for ProxyHandler {
    async fn send_packet(&mut self, data: Vec<u8>) -> io::Result<()> {
        if let Err(err) = self.response_tx.send((self.src_addr, data)).await {
            error!("UDP associate response channel error: {}", err);
        }
        Ok(())
    }
}

async fn parse_packet(pkt: &[u8]) -> io::Result<(Address, Vec<u8>)> {
    // PKT = UdpAssociateHeader + PAYLOAD
    let mut cur = Cursor::new(pkt);

    let header = UdpAssociateHeader::read_from(&mut cur).await?;

    if header.frag != 0 {
        error!("received UDP associate with frag != 0, which is not supported by ShadowSocks");
        let err = io::Error::new(ErrorKind::Other, "unsupported UDP fragmentation");
        return Err(err);
    }

    let addr = header.address;

    // The remaining is PAYLOAD
    let mut payload = Vec::new();
    cur.read_to_end(&mut payload)?;

    Ok((addr, payload))
}

fn assemble_packet(addr: Address, pkt: &[u8]) -> Bytes {
    let header = UdpAssociateHeader {
        frag: 0x00,
        address: addr,
    };

    let mut buf = BytesMut::with_capacity(header.serialized_len() + pkt.len());
    header.write_to_buf(&mut buf);
    buf.extend_from_slice(pkt);

    buf.freeze()
}

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local_addr.as_ref().expect("local config");
    let bind_addr = local_addr.bind_addr(&*context).await?;

    let l = create_udp_socket(&bind_addr).await?;
    let local_addr = l.local_addr().expect("determine port bound to");

    let balancer = PlainPingBalancer::new(context.clone(), ServerType::Udp).await;

    let (mut r, mut w) = l.split();

    info!("shadowsocks UDP listening on {}", local_addr);

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

            let payload = assemble_packet(Address::SocketAddress(src), &pkt);

            if let Err(err) = w.send_to(&payload, &src).await {
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
            // See `relay::udprelay::utils::create_udp_socket` for more detail.
            continue;
        }

        // Parse it for validating
        let (target, payload) = match parse_packet(pkt).await {
            Ok(t) => t,
            Err(err) => {
                error!(
                    "received unrecognized UDP packet from {}, length {} bytes, error: {}",
                    src, recv_len, err
                );
                continue;
            }
        };

        // Check or (re)create an association
        {
            // Locks the whole association map
            let mut assoc_map = assoc_map.lock().await;

            // Get or create an association
            let assoc = match assoc_map.entry(src.to_string()) {
                Entry::Occupied(oc) => oc.into_mut(),
                Entry::Vacant(vc) => {
                    // Pick a server
                    let server = balancer.pick_server();

                    let sender = ProxyHandler {
                        src_addr: src,
                        response_tx: tx.clone(),
                    };

                    vc.insert(
                        ProxyAssociation::associate_with_acl(src, server, sender)
                            .await
                            .expect("create UDP association"),
                    )
                }
            };

            // FIXME: Lock is still kept for a mutable reference
            // Send to local -> remote task
            assoc.send(target, payload).await;
        }
    }
}
