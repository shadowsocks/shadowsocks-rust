//! UDP relay local server

use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use log::{error, info, trace};
use lru_time_cache::{Entry, LruCache};
use tokio::{self, sync::Mutex, time};

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        socks5::Address,
    },
};

use super::{
    association::{ProxyAssociation, ProxySend},
    tproxy_socket::TProxyUdpSocket,
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

type AssocMap = LruCache<String, ProxyAssociation>;
type SharedAssocMap = Arc<Mutex<AssocMap>>;

struct ProxyHandler {
    src_addr: SocketAddr,
    local_udp: TProxyUdpSocket,
    cache_key: String,
    assoc_map: SharedAssocMap,
}

impl ProxyHandler {
    pub fn new(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        cache_key: String,
        assoc_map: SharedAssocMap,
    ) -> io::Result<ProxyHandler> {
        // Create a socket binds to destination addr
        // This only works for systems that supports binding to non-local addresses
        let local_udp = TProxyUdpSocket::bind(&dst_addr)?;

        Ok(ProxyHandler {
            src_addr,
            local_udp,
            cache_key,
            assoc_map,
        })
    }
}

#[async_trait]
impl ProxySend for ProxyHandler {
    async fn send_packet(&mut self, data: Vec<u8>) -> io::Result<()> {
        self.local_udp.send_to(&data, &self.src_addr).await?;

        // Update LRU
        {
            let mut amap = self.assoc_map.lock().await;

            // Check or update expire time
            let _ = amap.get(&self.cache_key);
        }

        Ok(())
    }
}

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    if let Err(err) = super::sys::check_support_tproxy() {
        panic!("{}", err);
    }

    let local_addr = context.config().local.as_ref().expect("missing local config");
    let bind_addr = local_addr.bind_addr(&*context).await?;

    // let l = create_socket(&bind_addr).await?;
    let mut l = TProxyUdpSocket::bind(&bind_addr)?;
    let local_addr = l.local_addr().expect("determine port bound to");

    let balancer = PlainPingBalancer::new(context.clone(), ServerType::Udp).await;

    info!("shadowsocks UDP redirect listening on {}", local_addr);

    // NOTE: Associations are only eliminated by expire time
    // So it may exhaust all available file descriptors
    let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);
    let assoc_map: SharedAssocMap = Arc::new(Mutex::new(LruCache::with_expiry_duration(timeout)));

    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src, dst) = match time::timeout(timeout, l.recv_from(&mut pkt_buf)).await {
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

        // Check destination should be proxied or not
        let target = Address::SocketAddress(dst);
        let is_bypassed = context.check_target_bypassed(&target).await;

        // Check or (re)create an association
        {
            // Locks the whole association map
            let mut ref_assoc_map = assoc_map.lock().await;

            let cache_key = format!("{}-{}", src, dst);

            // Get or create an association
            let assoc = match ref_assoc_map.entry(cache_key.clone()) {
                Entry::Occupied(oc) => oc.into_mut(),
                Entry::Vacant(vc) => {
                    // Pick a server
                    let server = balancer.pick_server();

                    let sender = match ProxyHandler::new(src, dst, cache_key, assoc_map.clone()) {
                        Ok(s) => s,
                        Err(err) => {
                            error!("create UDP association for {} <-> {}, error: {}", src, dst, err);
                            continue;
                        }
                    };

                    let assoc = if is_bypassed {
                        ProxyAssociation::associate_bypassed(src, server, sender).await
                    } else {
                        ProxyAssociation::associate_proxied(src, server, sender).await
                    }
                    .expect("create UDP association");

                    vc.insert(assoc)
                }
            };

            // FIXME: Lock is still kept for a mutable reference
            // Send to local -> remote task
            assoc.send(target, pkt.to_vec()).await;
        }
    }
}
