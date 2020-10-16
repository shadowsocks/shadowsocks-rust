//! UDP relay local server

use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use log::{debug, error, info, trace};
use tokio::{self, sync::mpsc};

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        socks5::Address,
        sys::create_udp_socket,
    },
};

use super::{
    association::{ProxyAssociation, ProxyAssociationManager, ProxySend},
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

#[derive(Clone)]
struct ProxyHandler {
    src_addr: SocketAddr,
    response_tx: mpsc::Sender<(SocketAddr, Address, Vec<u8>)>,
}

#[async_trait]
impl ProxySend for ProxyHandler {
    async fn send_packet(&mut self, addr: Address, data: Vec<u8>) -> io::Result<()> {
        if let Err(err) = self.response_tx.send((self.src_addr, addr, data)).await {
            error!("UDP associate response channel error: {}", err);
        }
        Ok(())
    }
}

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local_addr.as_ref().expect("local config");
    let bind_addr = local_addr.bind_addr(&context).await?;

    let l = create_udp_socket(&bind_addr).await?;
    let local_addr = l.local_addr().expect("could not determine port bound to");

    let balancer = PlainPingBalancer::new(context.clone(), ServerType::Udp).await;

    let r = Arc::new(l);
    let w = r.clone();

    let forward_target = context.config().forward.clone().expect("`forward` address in config");

    info!(
        "shadowsocks UDP tunnel listening on {}, forward to {}",
        local_addr, forward_target
    );

    let assoc_manager = ProxyAssociationManager::new(context.config());
    let assoc_manager_cloned = assoc_manager.clone();

    let mut pkt_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    // FIXME: Channel size 1024?
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Address, Vec<u8>)>(1024);
    tokio::spawn(async move {
        let assoc_manager = assoc_manager_cloned;

        while let Some((src, _, pkt)) = rx.recv().await {
            let cache_key = src.to_string();
            if !assoc_manager.keep_alive(&cache_key).await {
                debug!(
                    "UDP association {} <-> ... is already expired, throwing away packet {} bytes",
                    src,
                    pkt.len()
                );
                continue;
            }

            if let Err(err) = w.send_to(&pkt, &src).await {
                error!("UDP packet send failed, err: {:?}", err);
                break;
            }
        }

        // FIXME: How to stop the outer listener Future?
    });

    loop {
        let (recv_len, src) = r.recv_from(&mut pkt_buf).await?;

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

        // Check or (re)create an association
        let res = assoc_manager
            .send_packet(src.to_string(), forward_target.clone(), pkt.to_vec(), async {
                // Pick a server
                let server = balancer.pick_server();

                let sender = ProxyHandler {
                    src_addr: src,
                    response_tx: tx.clone(),
                };

                ProxyAssociation::associate_with_acl(src, server, sender).await
            })
            .await;

        if let Err(err) = res {
            debug!("failed to create UDP association, {}", err);
        }
    }
}
