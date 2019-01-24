//! UDP relay proxy server

use std::{
    io::{self, Cursor, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{self, stream::futures_unordered, Future, Stream};
use log::{debug, error, info};
use tokio::{self, net::UdpSocket, util::FutureExt};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{boxed_future, dns_resolver::resolve, socks5::Address},
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    PacketStream,
    SendDgramRc,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

fn resolve_remote_addr(
    context: SharedContext,
    addr: Address,
) -> impl Future<Item = SocketAddr, Error = io::Error> + Send {
    match addr {
        Address::SocketAddress(s) => {
            if context.config().forbidden_ip.contains(&s.ip()) {
                let err = io::Error::new(
                    ErrorKind::Other,
                    format!("{} is forbidden, failed to connect {}", s.ip(), s),
                );
                return boxed_future(futures::done(Err(err)));
            }

            boxed_future(futures::finished(s))
        }
        Address::DomainNameAddress(dname, port) => {
            let fut = resolve(context, &dname, port, true).map(move |vec_ipaddr| {
                assert!(!vec_ipaddr.is_empty());
                vec_ipaddr[0]
            });
            boxed_future(fut)
        }
    }
}

fn listen(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> impl Future<Item = (), Error = io::Error> + Send {
    let listen_addr = *svr_cfg.addr().listen_addr();
    info!("ShadowSocks UDP listening on {}", listen_addr);
    futures::lazy(move || UdpSocket::bind(&listen_addr)).and_then(move |socket| {
        let socket = Arc::new(Mutex::new(socket));
        PacketStream::new(socket.clone()).for_each(move |(pkt, src)| {
            let svr_cfg = svr_cfg.clone();
            let svr_cfg_cloned = svr_cfg.clone();
            let socket = socket.clone();
            let context = context.clone();
            let timeout = svr_cfg.timeout();
            let rel = futures::lazy(move || decrypt_payload(svr_cfg.method(), svr_cfg.key(), &pkt))
                .and_then(move |payload| {
                    // Read Address in the front (ShadowSocks protocol)
                    Address::read_from(Cursor::new(payload))
                        .map_err(From::from)
                        .and_then(move |(r, addr)| {
                            let header_len = r.position() as usize;
                            let mut payload = r.into_inner();
                            payload.drain(..header_len);
                            let body = payload;

                            debug!("UDP ASSOCIATE {} -> {}, payload length {} bytes", src, addr, body.len());
                            Ok((addr, body))
                        })
                        .and_then(|(addr, body)| {
                            let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                            UdpSocket::bind(&local_addr).map(|remote_udp| (remote_udp, addr, body))
                        })
                        .and_then(|(remote_udp, addr, body)| {
                            resolve_remote_addr(context, addr.clone())
                                .and_then(|addr| remote_udp.send_dgram(body, &addr))
                                .map(|(remote_udp, _)| (remote_udp, addr))
                        })
                })
                .and_then(move |(remote_udp, addr)| {
                    let buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
                    let to = timeout.unwrap_or(Duration::from_secs(5));
                    let caddr = addr.clone();
                    remote_udp
                        .recv_dgram(buf)
                        .timeout(to)
                        .map_err(move |err| match err.into_inner() {
                            Some(e) => e,
                            None => {
                                error!(
                                    "Udp associate waiting datagram {} -> {} timed out in {:?}",
                                    src, caddr, to
                                );
                                io::Error::new(io::ErrorKind::TimedOut, "udp recv timed out")
                            }
                        })
                        .and_then(|(_remote_udp, buf, n, _from)| {
                            let svr_cfg = svr_cfg_cloned;

                            let mut send_buf = Vec::new();
                            addr.write_to_buf(&mut send_buf);
                            send_buf.extend_from_slice(&buf[..n]);
                            encrypt_payload(svr_cfg.method(), svr_cfg.key(), &send_buf).map(|buf| (buf, addr))
                        })
                })
                .and_then(move |(buf, addr)| {
                    debug!("UDP ASSOCIATE {} <- {}, payload length {} bytes", src, addr, buf.len());

                    let to = timeout.unwrap_or(Duration::from_secs(5));
                    let caddr = addr.clone();
                    SendDgramRc::new(socket, buf, src)
                        .timeout(to)
                        .map_err(move |err| match err.into_inner() {
                            Some(e) => e,
                            None => {
                                error!(
                                    "Udp associate sending datagram {} <- {} timed out in {:?}",
                                    src, caddr, to
                                );
                                io::Error::new(io::ErrorKind::TimedOut, "udp send timed out")
                            }
                        })
                })
                .map(|_| ());

            tokio::spawn(rel.map_err(|err| {
                error!("Udp relay error: {}", err);
            }));

            Ok(())
        })
    })
}

/// Starts a UDP relay server
pub fn run(context: SharedContext) -> impl Future<Item = (), Error = io::Error> + Send {
    let mut vec_fut = Vec::new();

    for svr in &context.config().server {
        let svr_cfg = Arc::new(svr.clone());

        let svr_fut = listen(context.clone(), svr_cfg);
        vec_fut.push(boxed_future(svr_fut));
    }

    futures_unordered(vec_fut).into_future().then(|res| match res {
        Ok(..) => {
            error!("One of UDP servers exited unexpectly without error");
            let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
            Err(err)
        }
        Err((err, ..)) => {
            error!("One of UDP servers exited unexpectly with error {}", err);
            Err(err)
        }
    })
}
