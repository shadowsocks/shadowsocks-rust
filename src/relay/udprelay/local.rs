//! UDP relay local server

use std::{
    io::{self, Cursor, ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use log::{debug, error};
use tokio::{
    self,
    net::{udp::split::UdpSocketSendHalf, UdpSocket},
};

use crate::{
    config::{ServerAddr, ServerConfig},
    context::SharedContext,
    relay::{
        dns_resolver::resolve,
        loadbalancing::server::{LoadBalancer, RoundRobin},
        socks5::{Address, UdpAssociateHeader},
        utils::try_timeout,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

/// Resolves server address to SocketAddr
async fn resolve_server_addr(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> io::Result<SocketAddr> {
    match *svr_cfg.addr() {
        // Return directly if it is a SocketAddr
        ServerAddr::SocketAddr(ref addr) => Ok(*addr),
        // Resolve domain name to SocketAddr
        ServerAddr::DomainName(ref dname, port) => {
            let vec_ipaddr = resolve(context, dname, port, false).await?;
            assert!(!vec_ipaddr.is_empty());
            Ok(vec_ipaddr[0])
        }
    }
}

async fn udp_associate(
    context: SharedContext,
    svr_cfg: Arc<ServerConfig>,
    l: &mut UdpSocketSendHalf,
    pkt: Vec<u8>,
    src: SocketAddr,
) -> io::Result<()> {
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
    cur.read_to_end(&mut payload)?;

    // Connect to server
    let remote_addr = resolve_server_addr(context, svr_cfg.clone()).await?;

    // Binds to 0.0.0.0:0 (let system choose a random port)
    // FIXME: Create a UdpSocket for every UDP associate requests
    let local_addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let mut remote_udp = UdpSocket::bind(&local_addr).await?;

    // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
    let mut send_buf = Vec::new();
    addr.write_to_buf(&mut send_buf);
    send_buf.extend_from_slice(&payload);
    let send_buf = encrypt_payload(svr_cfg.method(), svr_cfg.key(), &send_buf)?;

    debug!(
        "UDP ASSOCIATE {} -> {}, payload length {} bytes",
        src,
        addr,
        payload.len()
    );

    let timeout = svr_cfg.udp_timeout().unwrap_or(DEFAULT_TIMEOUT);

    // Write to remote socket CLIENT -> SERVER
    let send_len = try_timeout(remote_udp.send_to(&send_buf, &remote_addr), Some(timeout)).await?;
    assert_eq!(send_buf.len(), send_len);

    // Waiting for response from server SERVER -> CLIENT
    // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
    let mut remote_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    let remote_recv_len = try_timeout(remote_udp.recv(&mut remote_buf), Some(timeout)).await?;

    let recv_buf = decrypt_payload(svr_cfg.method(), svr_cfg.key(), &remote_buf[..remote_recv_len])?;

    // SERVER -> CLIENT protocol: ADDRESS + PAYLOAD
    let mut cur = Cursor::new(&recv_buf);

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
    cur.read_to_end(&mut data)?;

    // Write back
    let send_len = l.send_to(&data, &src).await?;
    assert_eq!(data.len(), send_len);

    Ok(())
}

async fn listen(context: SharedContext, l: UdpSocket) -> io::Result<()> {
    let mut balancer = RoundRobin::new(context.config());

    let (mut r, mut w) = l.split();

    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src) = r.recv_from(&mut pkt_buf).await?;

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        // Copy bytes, because udp_associate runs in another tokio Task
        let pkt = pkt_buf[..recv_len].to_vec();

        let svr_cfg = balancer.pick_server();

        let assoc = async {
            match udp_associate(context.clone(), svr_cfg.clone(), &mut w, pkt, src).await {
                Ok(..) => (),
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
    listen(context, listener).await
}
