//! UDP relay local server

use std::{io, net::SocketAddr};

use async_trait::async_trait;
use log::{debug, info, trace};

use crate::{
    config::RedirType,
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        redir::UdpSocketRedirExt,
        socks5::Address,
    },
};

use super::{
    association::{ProxyAssociation, ProxyAssociationManager, ProxySend},
    redir::sys::UdpRedirSocket,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

struct ProxyHandler {
    ty: RedirType,
    src_addr: SocketAddr,
    cache_key: String,
    assoc_map: ProxyAssociationManager<String>,
}

impl ProxyHandler {
    pub fn new(
        ty: RedirType,
        src_addr: SocketAddr,
        cache_key: String,
        assoc_map: ProxyAssociationManager<String>,
    ) -> io::Result<ProxyHandler> {
        Ok(ProxyHandler {
            ty,
            src_addr,
            cache_key,
            assoc_map,
        })
    }
}

#[async_trait]
impl ProxySend for ProxyHandler {
    async fn send_packet(&mut self, addr: Address, data: Vec<u8>) -> io::Result<()> {
        // Redirect only if the target is a SocketAddress
        if let Address::SocketAddress(ref dst_addr) = addr {
            // Create a socket binds to destination addr
            // This only works for systems that supports binding to non-local addresses
            let mut local_udp = UdpRedirSocket::bind(self.ty, dst_addr)?;

            local_udp.send_to(&data, &self.src_addr).await?;

            // Update LRU
            self.assoc_map.keep_alive(&self.cache_key).await;

            return Ok(());
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Address from remote is not a socket addr",
        ))
    }
}

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local_addr.as_ref().expect("missing local config");
    let bind_addr = local_addr.bind_addr(&context).await?;

    let ty = context.config().udp_redir;

    // let l = create_socket(&bind_addr).await?;
    let mut l = UdpRedirSocket::bind(ty, &bind_addr)?;
    let local_addr = l.local_addr().expect("determine port bound to");

    let balancer = PlainPingBalancer::new(context.clone(), ServerType::Udp).await;

    info!("shadowsocks UDP redirect listening on {}", local_addr);

    let assoc_manager = ProxyAssociationManager::new(context.config());

    let mut pkt_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src, dst) = l.recv_from_redir(&mut pkt_buf).await?;

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
        let cache_key = format!("{}-{}", src, dst);
        let cache_key_cloned = cache_key.clone();
        let res = assoc_manager
            .send_packet(cache_key, target, pkt.to_vec(), async {
                // Pick a server
                let server = balancer.pick_server();

                let sender = match ProxyHandler::new(ty, src, cache_key_cloned, assoc_manager.clone()) {
                    Ok(s) => s,
                    Err(err) => {
                        debug!("create UDP association for {} <-> {}, error: {}", src, dst, err);
                        return Err(err);
                    }
                };

                if is_bypassed {
                    ProxyAssociation::associate_bypassed(src, server, sender).await
                } else {
                    ProxyAssociation::associate_proxied(src, server, sender).await
                }
            })
            .await;

        if let Err(err) = res {
            debug!("failed to create UDP association, {}", err);
        }
    }
}
