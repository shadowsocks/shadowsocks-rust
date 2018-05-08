//! UDP relay proxy server

use std::io::{self, Cursor, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use futures::{self, Future, Stream};

use tokio;
use tokio::net::UdpSocket;
use tokio_io::IoFuture;

use config::{Config, ServerConfig};
use relay::boxed_future;
use relay::dns_resolver::resolve;
use relay::socks5::Address;

use super::crypto_io::{decrypt_payload, encrypt_payload};
use super::MAXIMUM_UDP_PAYLOAD_SIZE;
use super::{PacketStream, SendDgramRc};

fn resolve_remote_addr(config: Arc<Config>, addr: Address) -> IoFuture<SocketAddr> {
    match addr {
        Address::SocketAddress(s) => {
            if config.forbidden_ip.contains(&s.ip()) {
                let err = io::Error::new(ErrorKind::Other,
                                         format!("{} is forbidden, failed to connect {}", s.ip(), s));
                return boxed_future(futures::done(Err(err)));
            }

            boxed_future(futures::finished(s))
        }
        Address::DomainNameAddress(dname, port) => {
            let fut = resolve(config, &dname, port, true).map(move |vec_ipaddr| {
                                                                  assert!(!vec_ipaddr.is_empty());
                                                                  vec_ipaddr[0]
                                                              });
            boxed_future(fut)
        }
    }
}

fn listen(config: Arc<Config>, svr_cfg: Arc<ServerConfig>) -> IoFuture<()> {
    let listen_addr = *svr_cfg.addr().listen_addr();
    info!("ShadowSocks UDP listening on {}", listen_addr);
    let fut = futures::lazy(move || UdpSocket::bind(&listen_addr)).and_then(move |socket| {
        let socket = Arc::new(Mutex::new(socket));
        PacketStream::new(socket.clone()).for_each(move |(pkt, src)| {
            let svr_cfg = svr_cfg.clone();
            let svr_cfg_cloned = svr_cfg.clone();
            let socket = socket.clone();
            let config = config.clone();
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
                                          UdpSocket::bind(&local_addr)
                                              .map(|remote_udp| (remote_udp, addr, body))
                                      })
                            .and_then(|(remote_udp, addr, body)| {
                                          resolve_remote_addr(config, addr.clone())
                                              .and_then(|addr| remote_udp.send_dgram(body, &addr))
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

            tokio::spawn(rel.map_err(|err| {
                                         error!("Udp relay error: {}", err);
                                     }));

            Ok(())
        })
    });
    boxed_future(fut)
}

/// Starts a UDP relay server
pub fn run(config: Arc<Config>) -> IoFuture<()> {
    let mut fut = None;

    for svr in &config.server {
        let svr_cfg = Arc::new(svr.clone());

        let svr_fut = listen(config.clone(), svr_cfg);
        fut = match fut {
            None => Some(svr_fut),
            Some(fut) => Some(boxed_future(fut.join(svr_fut).map(|_| ()))),
        };
    }

    fut.expect("Should have at least one server")
}
