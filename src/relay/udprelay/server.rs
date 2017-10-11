//! UDP relay proxy server

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;

use futures::{self, Future, Stream};

use tokio_core::net::UdpSocket;

use config::ServerConfig;
use relay::{BoxIoFuture, boxed_future};
use relay::Context;
use relay::dns_resolver::resolve;
use relay::socks5::Address;

use super::MAXIMUM_UDP_PAYLOAD_SIZE;
use super::{PacketStream, SendDgramRc};
use super::crypto_io::{decrypt_payload, encrypt_payload};

fn resolve_remote_addr(addr: Address) -> BoxIoFuture<SocketAddr> {
    match addr {
        Address::SocketAddress(s) => boxed_future(futures::finished(s)),
        Address::DomainNameAddress(ref dname, port) => {
            let fut = resolve(dname).map(move |vec_ipaddr| {
                let ipaddr = vec_ipaddr.into_iter()
                                       .next()
                                       .expect("Resolved empty IP list");
                match ipaddr {
                    IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                    IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                }
            });
            boxed_future(fut)
        }
    }
}

fn listen(svr_cfg: Rc<ServerConfig>) -> BoxIoFuture<()> {
    let listen_addr = *svr_cfg.addr().listen_addr();
    info!("ShadowSocks UDP listening on {}", listen_addr);
    let fut = futures::lazy(move || Context::with(|ctx| UdpSocket::bind(&listen_addr, ctx.handle())))
        .and_then(move |socket| {
            let socket = Rc::new(socket);
            PacketStream::new(socket.clone()).for_each(move |(pkt, src)| {
                let svr_cfg = svr_cfg.clone();
                let svr_cfg_cloned = svr_cfg.clone();
                let socket = socket.clone();
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

                                info!("UDP ASSOCIATE {} -> {}, payload length {} bytes", src, addr, body.len());
                                Ok((addr, body))
                            })
                            .and_then(|(addr, body)| {
                                          let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
                                          Context::with(|ctx| UdpSocket::bind(&local_addr, ctx.handle()))
                                              .map(|remote_udp| (remote_udp, addr, body))
                                      })
                            .and_then(|(remote_udp, addr, body)| {
                                          resolve_remote_addr(addr.clone())
                                              .and_then(|addr| remote_udp.send_dgram(body, addr))
                                              .map(|(remote_udp, _)| (remote_udp, addr))
                                      })
                    })
                    .and_then(|(remote_udp, addr)| {
                        let buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
                        remote_udp.recv_dgram(buf)
                                  .and_then(|(_remote_udp, buf, n, _from)| {
                            let svr_cfg = svr_cfg_cloned;

                            let mut send_buf = Vec::new();
                            addr.write_to_buf(&mut send_buf);
                            send_buf.extend_from_slice(&buf[..n]);
                            encrypt_payload(svr_cfg.method(), svr_cfg.key(), &send_buf).map(|buf| (buf, addr))
                        })
                    })
                    .and_then(move |(buf, addr)| {
                                  info!("UDP ASSOCIATE {} <- {}, payload length {} bytes", src, addr, buf.len());
                                  SendDgramRc::new(socket, buf, src)
                              })
                    .map(|_| ());

                Context::with(|ctx| {
                                  let handle = ctx.handle();
                                  handle.spawn(rel.map_err(|err| {
                                                               error!("Udp relay error: {}", err);
                                                           }));
                              });

                Ok(())
            })
        });
    boxed_future(fut)
}

/// Starts a UDP relay server
pub fn run() -> BoxIoFuture<()> {
    let mut fut = None;

    Context::with(|ctx| {
        let config = ctx.config();
        for svr in &config.server {
            let svr_cfg = Rc::new(svr.clone());

            let svr_fut = listen(svr_cfg);
            fut = match fut {
                None => Some(svr_fut),
                Some(fut) => Some(boxed_future(fut.join(svr_fut).map(|_| ()))),
            };
        }

        fut.expect("Should have at least one server")
    })
}
