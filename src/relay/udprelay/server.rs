//! UDP relay proxy server

use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use futures::stream::FuturesUnordered;
use futures::{self, StreamExt};
use log::{debug, error, info};
use lru_time_cache::{Entry, LruCache};
use tokio;
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::ServerConfig;
use crate::context::SharedContext;
use crate::relay::{socks5::Address, utils::try_timeout};

use super::crypto_io::{decrypt_payload, encrypt_payload};
use super::MAXIMUM_UDP_PAYLOAD_SIZE;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(unused_variables)] // `context` is only used if trust-dns is enabled
async fn udp_associate(
    context: SharedContext,
    svr_cfg: Arc<ServerConfig>,
    decrypted_pkt: Vec<u8>,
    src: SocketAddr,
) -> io::Result<Vec<u8>> {
    // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
    let mut cur = Cursor::new(decrypted_pkt);

    let addr = Address::read_from(&mut cur).await?;

    // Take out internal buffer for optimizing one byte copy
    let header_len = cur.position() as usize;
    let decrypted_pkt = cur.into_inner();
    let body = &decrypted_pkt[header_len..];

    debug!("UDP ASSOCIATE {} -> {}, payload length {} bytes", src, addr, body.len());

    // FIXME: Create one UdpSocket for one associate
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let mut remote_udp = UdpSocket::bind(&local_addr).await?;

    let timeout = svr_cfg.udp_timeout().unwrap_or(DEFAULT_TIMEOUT);

    // Writes body to remote
    let send_len = match addr {
        Address::SocketAddress(ref remote_addr) => {
            try_timeout(remote_udp.send_to(&body, remote_addr), Some(timeout)).await?
        }
        #[cfg(feature = "trust-dns")]
        Address::DomainNameAddress(ref dname, port) => {
            use crate::relay::dns_resolver::resolve;

            let vec_ipaddr = resolve(context, dname, port, false).await?;
            assert!(!vec_ipaddr.is_empty());

            try_timeout(remote_udp.send_to(&body, &vec_ipaddr[0]), Some(timeout)).await?
        }
        #[cfg(not(feature = "trust-dns"))]
        Address::DomainNameAddress(ref dname, port) => {
            try_timeout(remote_udp.send_to(&body, (dname.as_str(), port)), Some(timeout)).await?
        }
    };
    assert_eq!(body.len(), send_len);

    // Waiting for response from server SERVER -> CLIENT
    // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
    let mut remote_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    let remote_recv_len = try_timeout(remote_udp.recv(&mut remote_buf), Some(timeout)).await?;

    // Making response packet, SERVER -> CLIENT: ADDRESS + PAYLOAD
    let mut send_buf = Vec::new();
    addr.write_to_buf(&mut send_buf);
    send_buf.extend_from_slice(&remote_buf[..remote_recv_len]);

    debug!(
        "UDP ASSOCIATE {} <- {}, payload length {} bytes",
        src,
        addr,
        send_buf.len()
    );

    Ok(send_buf)
}

// Represent a UDP association
struct UdpAssociation {
    tx: mpsc::Sender<(Address, Vec<u8>)>,
}

impl UdpAssociation {
    /// Create an association with addr
    async fn associate(
        svr_cfg: Arc<ServerConfig>,
        src_addr: SocketAddr,
        mut response_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    ) -> io::Result<UdpAssociation> {
        debug!("Created UDP Association for {}", src_addr);

        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let remote_udp = UdpSocket::bind(&local_addr).await?;

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, mut rx) = mpsc::channel::<(Address, Vec<u8>)>(1024);

        // Splits socket into sender and receiver
        let (mut receiver, mut sender) = remote_udp.split();

        let timeout = svr_cfg.udp_timeout().unwrap_or(DEFAULT_TIMEOUT);

        // local -> remote
        tokio::spawn(async move {
            while let Some((addr, pkt)) = rx.recv().await {
                debug!(
                    "UDP ASSOCIATE {} -> {}, payload length {} bytes",
                    src_addr,
                    addr,
                    pkt.len(),
                );

                // pkt is already a raw packet, so just send it
                if let Err(err) = UdpAssociation::relay_l2r(&addr, &mut sender, &pkt[..], timeout).await {
                    error!("Failed to send packet to {}, error: {}", addr, err);

                    // FIXME: Ignore? Or how to deal with it?
                }
            }

            debug!("UDP ASSOCIATE {} -> .. finished", src_addr);
        });

        // local <- remote
        tokio::spawn(async move {
            loop {
                // Read and send back to source
                if let Err(err) = UdpAssociation::relay_r2l(src_addr, &mut receiver, timeout, &mut response_tx).await {
                    error!("Failed to receive packet, {} <- .., error: {}", src_addr, err);
                    break;
                }
            }

            debug!("UDP ASSOCIATE {} <- .. finished", src_addr);
        });

        Ok(UdpAssociation { tx })
    }

    /// Relay packets from local to remote
    async fn relay_l2r(addr: &Address, remote_udp: &mut SendHalf, pkt: &[u8], timeout: Duration) -> io::Result<()> {
        let send_len = match addr {
            Address::SocketAddress(ref remote_addr) => {
                try_timeout(remote_udp.send_to(pkt, remote_addr), Some(timeout)).await?
            }
            #[cfg(feature = "trust-dns")]
            Address::DomainNameAddress(ref dname, port) => {
                use crate::relay::dns_resolver::resolve;

                let vec_ipaddr = resolve(context, dname, port, false).await?;
                assert!(!vec_ipaddr.is_empty());

                try_timeout(remote_udp.send_to(pkt, &vec_ipaddr[0]), Some(timeout)).await?
            }
            #[cfg(not(feature = "trust-dns"))]
            Address::DomainNameAddress(ref dname, port) => {
                // try_timeout(remote_udp.send_to(pkt, (dname.as_str(), port)), Some(timeout)).await?
                unimplemented!("tokio's UdpSocket SendHalf doesn't support ToSocketAddrs");
            }
        };

        assert_eq!(pkt.len(), send_len);

        Ok(())
    }

    /// Relay packets from remote to local
    async fn relay_r2l(
        src_addr: SocketAddr,
        remote_udp: &mut RecvHalf,
        timeout: Duration,
        response_tx: &mut mpsc::Sender<(SocketAddr, Vec<u8>)>,
    ) -> io::Result<()> {
        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut remote_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let remote_recv_len = try_timeout(remote_udp.recv(&mut remote_buf), Some(timeout)).await?;

        // Send back to src_addr
        if let Err(err) = response_tx
            .send((src_addr, remote_buf[..remote_recv_len].to_vec()))
            .await
        {
            error!("Failed to send packet into response channel, error: {}", err);

            // FIXME: What to do? Ignore?
        }

        Ok(())
    }

    async fn send(&mut self, remote_addr: &Address, pkt: &[u8]) -> bool {
        match self.tx.send((remote_addr.clone(), pkt.to_vec())).await {
            Ok(..) => true,
            Err(err) => {
                error!("Failed to send packet, error: {}", err);
                false
            }
        }
    }
}

async fn listen(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> io::Result<()> {
    let listen_addr = *svr_cfg.addr().listen_addr();
    info!("ShadowSocks UDP listening on {}", listen_addr);

    let listener = UdpSocket::bind(&listen_addr).await?;
    let (mut r, mut w) = listener.split();

    let svr_cfg_cloned = svr_cfg.clone();

    // FIXME: Channel size 1024?
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
    tokio::spawn(async move {
        let svr_cfg = svr_cfg_cloned;

        while let Some((src, pkt)) = rx.recv().await {
            // Encrypts
            let mut response_pkt = BytesMut::new();
            if let Err(err) = encrypt_payload(svr_cfg.method(), svr_cfg.key(), &pkt, &mut response_pkt) {
                error!("UDP packet encrypt failed, err: {:?}", err);
                continue;
            }

            if let Err(err) = w.send_to(&response_pkt, &src).await {
                error!("UDP packet send failed, err: {:?}", err);
                break;
            }
        }

        // FIXME: How to stop the outer listener Future?
    });

    let timeout = svr_cfg.udp_timeout().unwrap_or(DEFAULT_TIMEOUT);
    let mut assoc_map = LruCache::with_expiry_duration(timeout);

    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src) = r.recv_from(&mut pkt_buf).await?;

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let pkt = &pkt_buf[..recv_len];

        // First of all, decrypt payload CLIENT -> SERVER
        let decrypted_pkt = match decrypt_payload(svr_cfg.method(), svr_cfg.key(), pkt) {
            Ok(Some(pkt)) => pkt,
            Ok(None) => {
                error!("Failed to decrypt pkt in UDP relay, packet too short");
                continue;
            }
            Err(err) => {
                error!("Failed to decrypt pkt in UDP relay: {}", err);
                continue;
            }
        };

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut cur = Cursor::new(decrypted_pkt);

        let addr = Address::read_from(&mut cur).await?;

        // Take out internal buffer for optimizing one byte copy
        let header_len = cur.position() as usize;
        let decrypted_pkt = cur.into_inner();
        let body = &decrypted_pkt[header_len..];

        // Check or (re)create an association
        loop {
            let retry = {
                let assoc = match assoc_map.entry(src.to_string()) {
                    Entry::Occupied(oc) => oc.into_mut(),
                    Entry::Vacant(vc) => vc.insert(
                        UdpAssociation::associate(svr_cfg.clone(), src, tx.clone())
                            .await
                            .expect("Failed to create udp association"),
                    ),
                };

                !assoc.send(&addr, body).await
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
            error!("One of TCP servers exited unexpectly, result: {:?}", res);
            let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
            Err(err)
        }
        None => unreachable!(),
    }
}
