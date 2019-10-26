//! UDP DNS relay

use std::{
    io::{self, Cursor},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use dns_parser::Packet;
use futures::{
    self,
    future::{join_all, select_all, BoxFuture},
    StreamExt,
};
use log::{error, trace};
use tokio::{
    self,
    net::{
        udp::split::{UdpSocketRecvHalf, UdpSocketSendHalf},
        UdpSocket,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    MAXIMUM_UDP_PAYLOAD_SIZE,
};
use crate::{
    config::{ServerAddr, ServerConfig},
    context::SharedContext,
    relay::{dns_resolver::resolve, socks5::Address},
};

/// Starts a UDP DNS server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = *context.config().local.as_ref().unwrap();

    let listener = UdpSocket::bind(&local_addr).await?;
    listen(context, listener).await
}

async fn listen(context: SharedContext, l: UdpSocket) -> io::Result<()> {
    assert!(!context.config().server.is_empty());

    for svr in &context.config().server {
        let sock_addr = match *svr.addr() {
            ServerAddr::SocketAddr(ref addr) => vec![*addr],
            ServerAddr::DomainName(ref dom, ref port) => resolve(context.clone(), &*dom, *port, false).await?,
        };

        let local_addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let s = UdpSocket::bind(&local_addr).await?;
        let svr_cfg = Arc::new(svr.clone());
    }

    let mut svr_addr_futs = Vec::with_capacity(context.config().server.len());
    for svr in &context.config().server {
        let context = context.clone();
        svr_addr_futs.push(async move {
            match *svr.addr() {
                ServerAddr::SocketAddr(ref addr) => Ok((Arc::new(svr.clone()), *addr)),
                ServerAddr::DomainName(ref dname, port) => {
                    let vec_ipaddr = resolve(context, dname, port, false).await?;
                    assert!(!vec_ipaddr.is_empty());
                    Ok((Arc::new(svr.clone()), vec_ipaddr[0]))
                }
            }
        });
    }

    let (mut r, mut w) = l.split();

    let mut svr_fut = Vec::<BoxFuture<io::Result<()>>>::new();
    let mut vec_remote = Vec::<(UdpSocketSendHalf, Arc<ServerConfig>, SocketAddr)>::new();

    for svr_addr in join_all(svr_addr_futs.into_iter()).await {
        match svr_addr {
            Err(err) => {
                error!("Failed to resolve remote server address, err: {}", err);
                return Err(err);
            }

            Ok((svr_cfg, svr_addr)) => {
                let local_addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0);
                let remote_udp = UdpSocket::bind(&local_addr).await?;

                let (remote_r, remote_w) = remote_udp.split();
                vec_remote.push((remote_w, svr_cfg.clone(), svr_addr));

                svr_fut.push(Box::pin(handle_r2l(context.clone(), remote_r, &mut w, svr_cfg)));
            }
        }
    }

    svr_fut.push(Box::pin(handle_l2r(context, &mut r, vec_remote)));

    let (res, ..) = select_all(svr_fut.into_iter()).await;
    error!("One of DNS servers exited unexpectly, result: {:?}", res);
    let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
    Err(err)
}

async fn process_l2r(
    context: SharedContext,
    src: SocketAddr,
    socket: &mut UdpSocketSendHalf,
    svr_cfg: Arc<ServerConfig>,
    svr_addr: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    // Parse DNS packet
    let pkt = match Packet::parse(payload) {
        Ok(pkt) => pkt,
        Err(err) => {
            error!("Failed to parse DNS payload, err: {}", err);
            return Err(io::Error::new(io::ErrorKind::Other, "parse DNS packet failed"));
        }
    };

    trace!("DNS {} -> {} packet: {:?}", src, svr_cfg.addr(), pkt);

    // Create ShadowSocks CLIENT -> SERVER packet
    let mut buf = Vec::new();
    Address::SocketAddress(context.config().get_remote_dns()).write_to_buf(&mut buf);
    buf.extend_from_slice(&payload);
    let encrypted_payload = encrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf)?;

    let send_len = socket.send_to(&encrypted_payload, &svr_addr).await?;
    assert_eq!(encrypted_payload.len(), send_len);

    // Recorded into dns_query_cache
    let id = pkt.header.id;
    context.dns_query_cache().insert(id, (src, Instant::now()));

    Ok(())
}

async fn handle_l2r(
    context: SharedContext,
    l: &mut UdpSocketRecvHalf,
    server: Vec<(UdpSocketSendHalf, Arc<ServerConfig>, SocketAddr)>,
) -> io::Result<()> {
    assert!(!server.is_empty());

    let mut server_idx: usize = 0;

    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src) = l.recv_from(&mut pkt_buf).await?;

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let payload = &pkt_buf[..recv_len];

        let (ref socket, ref svr_cfg, svr_addr) = server[server_idx % server.len()];
        let (ni, _) = server_idx.overflowing_add(1);
        server_idx = ni;

        match process_l2r(context.clone(), src, &mut socket, svr_cfg.clone(), svr_addr, payload).await {
            Ok(..) => (),
            Err(err) => {
                error!("Failed to handle DNS relay Local -> Remote: {}", err);
            }
        }
    }
}

async fn process_r2l(
    context: SharedContext,
    src: SocketAddr,
    w: &mut UdpSocketSendHalf,
    svr_cfg: Arc<ServerConfig>,
    payload: &[u8],
) -> io::Result<()> {
    let mut cur = Cursor::new(payload);

    // Address is useless in this case
    let _ = Address::read_from(&mut cur).await?;

    let pos = cur.position() as usize;
    let payload = cur.into_inner();
    let body = &payload[pos..];

    let pkt = match Packet::parse(body) {
        Ok(pkt) => pkt,
        Err(err) => {
            error!("Failed to parse DNS payload, err: {}", err);
            return Err(io::Error::new(io::ErrorKind::Other, "parse DNS packet failed"));
        }
    };

    let taked_cli = context.dns_query_cache().remove(&pkt.header.id);
    match taked_cli {
        Some((cli_addr, start_time)) => {
            trace!(
                "DNS {} <- {} elapsed: {:?} packet: {:?}",
                cli_addr,
                src,
                Instant::now() - start_time,
                pkt,
            );

            // Send it back
            let send_len = w.send_to(body, &cli_addr).await?;
            assert_eq!(body.len(), send_len);
        }
        None => {
            error!(
                "DNS received packet id={} opcode={:?} but found no local endpoint",
                pkt.header.id, pkt.header.opcode
            );
        }
    }

    Ok(())
}

async fn handle_r2l(
    context: SharedContext,
    mut remote_r: UdpSocketRecvHalf,
    w: &mut UdpSocketSendHalf,
    svr_cfg: Arc<ServerConfig>,
) -> io::Result<()> {
    let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

    loop {
        let (recv_len, src) = remote_r.recv_from(&mut pkt_buf).await?;

        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let payload = &pkt_buf[..recv_len];

        // First of all, decrypt payload
        let payload = match decrypt_payload(svr_cfg.method(), svr_cfg.key(), payload) {
            Ok(p) => p,
            Err(err) => {
                error!("Failed to decrypt payload from: {}, err: {}", src, err);
                continue;
            }
        };

        match process_r2l(context.clone(), src, w, svr_cfg.clone(), &payload).await {
            Ok(..) => (),
            Err(err) => {
                error!("Failed to handle DNS relay Local <- Remote: {}", err);
            }
        }
    }
}
