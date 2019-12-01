//! UDP relay local server

use std::{
    io::{self, Cursor, ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use log::{debug, error, info, warn};
use tokio::{self, net::UdpSocket, sync::mpsc};

use crate::{
    config::{ServerAddr, ServerConfig},
    context::SharedContext,
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

#[allow(unused_variables)] // `context` is only used if trust-dns is enabled
async fn udp_associate(
    context: SharedContext,
    svr_cfg: Arc<ServerConfig>,
    pkt: Vec<u8>,
    src: SocketAddr,
) -> io::Result<Vec<u8>> {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

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
    Read::read_to_end(&mut cur, &mut payload)?;

    // Binds to 0.0.0.0:0 (let system choose a random port)
    // FIXME: Create a UdpSocket for every UDP associate requests
    let local_addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let mut remote_udp = UdpSocket::bind(&local_addr).await?;

    // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
    let mut send_buf = Vec::new();
    addr.write_to_buf(&mut send_buf);
    send_buf.extend_from_slice(&payload);

    debug!(
        "UDP ASSOCIATE {} -> {}, payload length {} bytes",
        src,
        addr,
        payload.len()
    );

    let timeout = svr_cfg.udp_timeout().unwrap_or(DEFAULT_TIMEOUT);

    // Write to remote socket CLIENT -> SERVER
    let mut encrypt_buf = BytesMut::new();
    encrypt_payload(svr_cfg.method(), svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

    let send_n = match *svr_cfg.addr() {
        ServerAddr::SocketAddr(ref addr) => try_timeout(remote_udp.send_to(&encrypt_buf, addr), Some(timeout)).await?,
        #[cfg(feature = "trust-dns")]
        ServerAddr::DomainName(ref dname, port) => {
            use crate::relay::dns_resolver::resolve;

            let vec_ipaddr = resolve(context, dname, port, false).await?;
            assert!(!vec_ipaddr.is_empty());

            try_timeout(remote_udp.send_to(&encrypt_buf, &vec_ipaddr[0]), Some(timeout)).await?
        }
        #[cfg(not(feature = "trust-dns"))]
        ServerAddr::DomainName(ref dname, port) => {
            try_timeout(remote_udp.send_to(&encrypt_buf, (dname.as_str(), port)), Some(timeout)).await?
        }
    };

    if send_n != encrypt_buf.len() {
        warn!(
            "Sent packet length {}, but expected length {}",
            send_n,
            encrypt_buf.len()
        );
    }

    // Waiting for response from server SERVER -> CLIENT
    // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
    let mut recv_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    let recv_n = try_timeout(remote_udp.recv(&mut recv_buf), Some(timeout)).await?;

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

    let payload_len = cur.get_ref().len() - cur.position() as usize;
    debug!(
        "UDP ASSOCIATE {} <- {}, payload length {} bytes",
        src, addr, payload_len
    );

    let mut data = Vec::new();
    UdpAssociateHeader::new(0, Address::SocketAddress(src)).write_to_buf(&mut data);

    // Copy payload directly
    Read::read_to_end(&mut cur, &mut data)?;

    Ok(data)
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

    loop {
        let (recv_len, src) = r.recv_from(&mut pkt_buf).await?;

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        // Copy bytes, because udp_associate runs in another tokio Task
        let pkt = pkt_buf[..recv_len].to_vec();

        let svr_cfg = balancer.pick_server();

        let context = context.clone();
        let svr_cfg = svr_cfg.clone();
        let mut tx = tx.clone();
        let assoc = async move {
            match udp_associate(context, svr_cfg, pkt, src).await {
                Ok(pkt) => {
                    if let Err(..) = tx.send((src, pkt)).await {
                        error!("UDP packet channel closed");
                    }
                }
                Err(err) => {
                    error!("Error occurs in UDP relay: {}", err);
                }
            }
        };

        tokio::spawn(assoc);
    }
}

/// Starts a UDP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = *context.config().local.as_ref().unwrap();

    let listener = UdpSocket::bind(&local_addr).await?;
    info!("ShadowSocks UDP listening on {}", local_addr);

    listen(context, listener).await
}
