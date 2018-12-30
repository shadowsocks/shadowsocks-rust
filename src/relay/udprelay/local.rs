//! UDP relay local server

use std::{
    io::{self, Cursor, ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{self, Future, Stream};

use tokio::{self, net::UdpSocket, util::FutureExt};

use config::{ServerAddr, ServerConfig};
use context::SharedContext;
use relay::{
    boxed_future,
    dns_resolver::resolve,
    loadbalancing::server::{LoadBalancer, RoundRobin},
    socks5::{Address, UdpAssociateHeader},
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    PacketStream,
    SendDgramRc,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

/// Resolves server address to SocketAddr
fn resolve_server_addr(
    context: SharedContext,
    svr_cfg: Arc<ServerConfig>,
) -> impl Future<Item = SocketAddr, Error = io::Error> + Send {
    match *svr_cfg.addr() {
        // Return directly if it is a SocketAddr
        ServerAddr::SocketAddr(ref addr) => boxed_future(futures::finished(*addr)),
        // Resolve domain name to SocketAddr
        ServerAddr::DomainName(ref dname, port) => {
            let fut = resolve(context, dname, port, false).map(move |vec_ipaddr| {
                assert!(!vec_ipaddr.is_empty());
                vec_ipaddr[0]
            });
            boxed_future(fut)
        }
    }
}

fn listen(context: SharedContext, l: UdpSocket) -> impl Future<Item = (), Error = io::Error> + Send {
    let socket = Arc::new(Mutex::new(l));
    let mut balancer = RoundRobin::new(context.config());

    PacketStream::new(socket.clone()).for_each(move |(pkt, src)| {
        let svr_cfg = balancer.pick_server();
        let svr_cfg_cloned = svr_cfg.clone();
        let svr_cfg_cloned_cloned = svr_cfg.clone();
        let socket = socket.clone();
        let context = context.clone();
        let timeout = *svr_cfg.udp_timeout();

        const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

        let rel = futures::lazy(|| UdpAssociateHeader::read_from(Cursor::new(pkt)))
            .map_err(From::from)
            .and_then(|(cur, header)| {
                if header.frag != 0 {
                    error!("Received UDP associate with frag != 0, which is not supported by ShadowSocks");
                    let err = io::Error::new(ErrorKind::Other, "unsupported UDP fragmentation");
                    Err(err)
                } else {
                    Ok((cur, header.address))
                }
            })
            .and_then(|(mut cur, addr)| {
                let svr_cfg = svr_cfg_cloned_cloned;

                let mut payload = Vec::new();
                cur.read_to_end(&mut payload).unwrap();

                resolve_server_addr(context, svr_cfg)
                    .and_then(|remote_addr| {
                        let local_addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0);
                        UdpSocket::bind(&local_addr).map(|remote_udp| (remote_udp, remote_addr))
                    })
                    .map(|(remote_udp, remote_addr)| (remote_udp, remote_addr, payload, addr))
            })
            .and_then(move |(remote_udp, remote_addr, payload, addr)| {
                let mut buf = Vec::new();
                addr.write_to_buf(&mut buf);
                buf.extend_from_slice(&payload);
                encrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf)
                    .map(|payload| (remote_udp, remote_addr, payload, addr))
            })
            .and_then(move |(remote_udp, remote_addr, payload, addr)| {
                debug!(
                    "UDP ASSOCIATE {} -> {}, payload length {} bytes",
                    src,
                    addr,
                    payload.len()
                );
                let to = timeout.unwrap_or(DEFAULT_TIMEOUT);
                let caddr = addr.clone();
                remote_udp
                    .send_dgram(payload, &remote_addr)
                    .timeout(to)
                    .map_err(move |err| match err.into_inner() {
                        Some(e) => e,
                        None => {
                            error!(
                                "Udp associate sending datagram {} -> {} timed out in {:?}",
                                src, caddr, to
                            );
                            io::Error::new(io::ErrorKind::TimedOut, "udp send timed out")
                        }
                    })
                    .map(|(remote_udp, _)| (remote_udp, addr))
            })
            .and_then(move |(remote_udp, addr)| {
                let buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
                let to = timeout.unwrap_or(DEFAULT_TIMEOUT);
                let caddr = addr.clone();
                remote_udp
                    .recv_dgram(buf)
                    .timeout(to)
                    .map_err(move |err| match err.into_inner() {
                        Some(e) => e,
                        None => {
                            error!(
                                "Udp associate waiting datagram {} <- {} timed out in {:?}",
                                src, caddr, to
                            );
                            io::Error::new(io::ErrorKind::TimedOut, "udp recv timed out")
                        }
                    })
                    .and_then(move |(_remote_udp, buf, n, _from)| {
                        let svr_cfg = svr_cfg_cloned;
                        decrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf[..n])
                    })
                    .map(|payload| (payload, addr))
            })
            .and_then(move |(payload, addr)| {
                Address::read_from(Cursor::new(payload))
                    .map_err(From::from)
                    .map(|(cur, ..)| (cur, addr))
            })
            .and_then(move |(mut cur, addr)| {
                let payload_len = cur.get_ref().len() - cur.position() as usize;
                debug!(
                    "UDP ASSOCIATE {} <- {}, payload length {} bytes",
                    src, addr, payload_len
                );

                let mut data = Vec::new();
                UdpAssociateHeader::new(0, Address::SocketAddress(src)).write_to_buf(&mut data);

                cur.read_to_end(&mut data).unwrap();

                SendDgramRc::new(socket, data, src)
            })
            .map(|_| ());

        tokio::spawn(rel.map_err(|err| {
            error!("Error occurs in UDP relay: {}", err);
        }));

        Ok(())
    })
}

/// Starts a UDP local server
pub fn run(context: SharedContext) -> impl Future<Item = (), Error = io::Error> + Send {
    let local_addr = *context.config().local.as_ref().unwrap();

    futures::lazy(move || {
        info!("ShadowSocks UDP Listening on {}", local_addr);

        UdpSocket::bind(&local_addr)
    })
    .and_then(move |l| listen(context, l))
}
