//! UDP relay local server

use std::{
    io::{self, Cursor, ErrorKind, Read},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, trace, warn};
use tokio::{self, net::UdpSocket, time};

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType},
        socks5::{Address, UdpAssociateHeader},
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
    cache_key: String,
    assoc_manager: ProxyAssociationManager<String>,
    tx: Arc<UdpSocket>,
}

impl ProxyHandler {
    fn new(src_addr: SocketAddr, assoc_manager: ProxyAssociationManager<String>, tx: Arc<UdpSocket>) -> ProxyHandler {
        ProxyHandler {
            src_addr,
            cache_key: src_addr.to_string(),
            assoc_manager,
            tx,
        }
    }
}

#[async_trait]
impl ProxySend for ProxyHandler {
    async fn send_packet(&mut self, addr: Address, data: Vec<u8>) -> io::Result<()> {
        if !self.assoc_manager.keep_alive(&self.cache_key).await {
            debug!(
                "UDP association {} <-> ... is already expired, throwing away packet {} bytes",
                self.src_addr,
                data.len()
            );
            return Ok(());
        }

        let payload = assemble_packet(addr, &data);

        match self.tx.send_to(&payload, &self.src_addr).await {
            Ok(n) => {
                if n < data.len() {
                    warn!(
                        "UDP association {} <- ... payload truncated, expecting {} bytes, but sent {} bytes",
                        self.src_addr,
                        payload.len(),
                        n
                    );
                }
                Ok(())
            }
            Err(err) => return Err(err),
        }
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
    let mut payload = Vec::with_capacity(pkt.len() - cur.position() as usize);
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
    let bind_addr = match context.config().udp_bind_addr {
        Some(ref bind_addr) => bind_addr.bind_addr(&context).await?,
        None => {
            let local_addr = context.config().local_addr.as_ref().expect("local config");
            local_addr.bind_addr(&context).await?
        }
    };

    let l = create_udp_socket(&bind_addr).await?;
    let local_addr = l.local_addr().expect("determine port bound to");

    let balancer = PlainPingBalancer::new(context.clone(), ServerType::Udp).await;

    let r = Arc::new(l);
    let w = r.clone();

    info!("shadowsocks SOCKS5 UDP listening on {}", local_addr);

    let assoc_manager = ProxyAssociationManager::new(context.config());

    let mut pkt_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src) = match r.recv_from(&mut pkt_buf).await {
            Ok(o) => o,
            Err(err) => {
                error!("recv_from failed with err: {}", err);
                time::sleep(Duration::from_secs(1)).await;
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
        let res = assoc_manager
            .send_packet(src.to_string(), target, payload, async {
                // Pick a server
                let server = balancer.pick_server();

                let sender = ProxyHandler::new(src, assoc_manager.clone(), w.clone());

                ProxyAssociation::associate_with_acl(src, server, sender).await
            })
            .await;

        if let Err(err) = res {
            debug!("failed to create UDP association, {}", err);
        }
    }
}
