//! UDP relay local server

use std::{
    io::{self, Cursor, ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use log::{debug, error, info, trace};
use lru_time_cache::{Entry, LruCache};
use tokio::{
    self,
    net::{
        udp::{RecvHalf, SendHalf},
        UdpSocket,
    },
    sync::mpsc,
    time,
};

use crate::{
    config::{ServerAddr, ServerConfig},
    context::{Context, SharedContext},
    relay::{
        loadbalancing::server::{LoadBalancer, RoundRobin},
        socks5::{Address, UdpAssociateHeader},
        utils::try_timeout,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

async fn parse_packet(pkt: &[u8]) -> io::Result<(Address, Vec<u8>)> {
    // PKT = UdpAssociateHeader + PAYLOAD
    let mut cur = Cursor::new(pkt);

    let header = UdpAssociateHeader::read_from(&mut cur).await?;

    if header.frag != 0 {
        error!("Received UDP associate with frag != 0, which is not supported by ShadowSocks");
        let err = io::Error::new(ErrorKind::Other, "unsupported UDP fragmentation");
        return Err(err);
    }

    let addr = header.address;

    // The remaining is PAYLOAD
    let mut payload = Vec::new();
    cur.read_to_end(&mut payload)?;

    Ok((addr, payload))
}

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
        mut response_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    ) -> io::Result<UdpAssociation> {
        debug!("Created UDP Association for {}", src_addr);

        // Create a socket for receiving packets
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let remote_udp = UdpSocket::bind(&local_addr).await?;

        // Create a channel for sending packets to remote
        // FIXME: Channel size 1024?
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        let close_flag = Arc::new(AtomicBool::new(false));

        // Splits socket into sender and receiver
        let (mut receiver, mut sender) = remote_udp.split();

        let timeout = svr_cfg.udp_timeout().unwrap_or(DEFAULT_TIMEOUT);

        // local -> remote
        let c_svr_cfg = svr_cfg.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                // pkt is already a raw packet, so just send it
                if let Err(err) =
                    UdpAssociation::relay_l2r(&*context, src_addr, &mut sender, &pkt[..], timeout, &*c_svr_cfg).await
                {
                    error!("Failed to send packet {} -> ..., error: {}", src_addr, err);

                    // FIXME: Ignore? Or how to deal with it?
                }
            }

            debug!("UDP ASSOCIATE {} -> .. finished", src_addr);
        });

        // local <- remote
        let closed = close_flag.clone();
        tokio::spawn(async move {
            while !closed.load(Ordering::Acquire) {
                // Read and send back to source
                match UdpAssociation::relay_r2l(src_addr, &mut receiver, timeout, &mut response_tx, &*svr_cfg).await {
                    Ok(..) => {}
                    Err(ref err) if err.kind() == ErrorKind::TimedOut => {
                        trace!("Receive packet timeout, {} <- ...", src_addr);
                    }
                    Err(err) => {
                        error!("Failed to receive packet, {} <- .., error: {}", src_addr, err);

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
        let (addr, payload) = parse_packet(&pkt).await?;

        debug!(
            "UDP ASSOCIATE {} -> {}, payload length {} bytes",
            src,
            addr,
            payload.len()
        );

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::new();
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(&payload);

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
        timeout: Duration,
        response_tx: &mut mpsc::Sender<(SocketAddr, Vec<u8>)>,
        svr_cfg: &ServerConfig,
    ) -> io::Result<()> {
        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut recv_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (recv_n, remote_addr) = try_timeout(remote_udp.recv_from(&mut recv_buf), Some(timeout)).await?;

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

        let header = UdpAssociateHeader::new(0, Address::SocketAddress(src_addr));

        header.write_to_buf(&mut payload);
        cur.read_to_end(&mut payload)?;

        debug!(
            "UDP ASSOCIATE {} <- {}, payload length {} bytes",
            src_addr,
            remote_addr,
            payload.len()
        );

        // Send back to src_addr
        if let Err(err) = response_tx.send((src_addr, payload)).await {
            error!("Failed to send packet into response channel, error: {}", err);

            // FIXME: What to do? Ignore?
        }

        Ok(())
    }

    async fn send(&mut self, pkt: &[u8]) -> bool {
        match self.tx.send(pkt.to_vec()).await {
            Ok(..) => true,
            Err(err) => {
                error!("Failed to send packet, error: {}", err);
                false
            }
        }
    }
}

async fn listen(context: SharedContext, l: UdpSocket) -> io::Result<()> {
    let mut balancer = RoundRobin::new(context.config());

    let (mut r, mut w) = l.split();

    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    // FIXME: Channel size 1024?
    let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(1024);
    tokio::spawn(async move {
        while let Some((src, pkt)) = rx.recv().await {
            if let Err(err) = w.send_to(&pkt, &src).await {
                error!("UDP packet send failed, err: {:?}", err);
                break;
            }
        }

        // FIXME: How to stop the outer listener Future?
    });

    let mut assoc_map =
        LruCache::with_expiry_duration_and_capacity(DEFAULT_TIMEOUT, 1024 /* Conservative, ulimit */);

    loop {
        let (recv_len, src) = match time::timeout(DEFAULT_TIMEOUT, r.recv_from(&mut pkt_buf)).await {
            Ok(r) => r?,
            Err(..) => {
                // Cleanup expired association
                // Do not consume this iterator, it will updates expire time of items that traversed
                let _ = assoc_map.iter();
                continue;
            }
        };

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        // Copy bytes, because udp_associate runs in another tokio Task
        let pkt = &pkt_buf[..recv_len];

        trace!("Received UDP packet from {}, length {} bytes", src, recv_len);

        // Pick a server
        let svr_cfg = balancer.pick_server();

        // Check or (re)create an association
        loop {
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

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = *context.config().local.as_ref().unwrap();

    let listener = UdpSocket::bind(&local_addr).await?;
    info!("ShadowSocks UDP listening on {}", local_addr);

    listen(context, listener).await
}
