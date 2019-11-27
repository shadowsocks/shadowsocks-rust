//! UDP relay proxy server

use std::{
    io::{self, Cursor},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use futures::{self, stream::FuturesUnordered, StreamExt};
use log::{debug, error, info};
use tokio::{self, net::UdpSocket, sync::mpsc};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{dns_resolver::resolve, socks5::Address, utils::try_timeout},
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

async fn resolve_remote_addr(context: SharedContext, addr: &Address) -> io::Result<SocketAddr> {
    match *addr {
        // Return directly if it is a SocketAddr
        Address::SocketAddress(ref addr) => Ok(*addr),
        // Resolve domain name to SocketAddr
        Address::DomainNameAddress(ref dname, port) => {
            let vec_ipaddr = resolve(context, dname, port, false).await?;
            assert!(!vec_ipaddr.is_empty());
            Ok(vec_ipaddr[0])
        }
    }
}

async fn udp_associate(
    context: SharedContext,
    svr_cfg: Arc<ServerConfig>,
    decrypted_pkt: Vec<u8>,
    src: SocketAddr,
) -> io::Result<Vec<u8>> {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

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
    let remote_addr = resolve_remote_addr(context, &addr).await?;
    let send_len = try_timeout(remote_udp.send_to(&body, &remote_addr), Some(timeout)).await?;
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

        let context = context.clone();
        let svr_cfg = svr_cfg.clone();
        let mut tx = tx.clone();
        tokio::spawn(async move {
            match udp_associate(context, svr_cfg, decrypted_pkt, src).await {
                Ok(pkt) => {
                    if let Err(..) = tx.send((src, pkt)).await {
                        error!("UDP packet channel closed");
                    }
                }
                Err(err) => {
                    error!("Error occurs in UDP relay: {}", err);
                }
            }
        });
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
