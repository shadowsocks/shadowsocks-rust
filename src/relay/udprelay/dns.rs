//! UDP DNS relay

use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use dns_parser::Packet;
use futures::future::join_all;
use futures::{self, Future, Stream};
use lru_cache::LruCache;
use tokio::net::UdpSocket;
use tokio_io::IoFuture;

use super::crypto_io::{decrypt_payload, encrypt_payload};
use super::{PacketStream, SendDgramRc, SharedUdpSocket};
use config::{Config, ServerAddr, ServerConfig};
use relay::boxed_future;
use relay::dns_resolver::resolve;
use relay::socks5::Address;

/// Starts a UDP DNS server
pub fn run(config: Arc<Config>) -> IoFuture<()> {
    let local_addr = *config.local.as_ref().unwrap();

    let fut = futures::lazy(move || {
        info!("ShadowSocks UDP DNS Listening on {}", local_addr);

        UdpSocket::bind(&local_addr)
    }).and_then(move |l| listen(config, l));

    boxed_future(fut)
}

fn listen(config: Arc<Config>, l: UdpSocket) -> IoFuture<()> {
    assert!(!config.server.is_empty());

    let mut svr_fut = Vec::with_capacity(config.server.len());
    for svr in &config.server {
        match *svr.addr() {
            ServerAddr::SocketAddr(ref addr) => {
                svr_fut.push(boxed_future(futures::finished::<_, io::Error>(vec![*addr])));
            }
            ServerAddr::DomainName(ref dom, ref port) => {
                svr_fut.push(resolve(config.clone(), &*dom, *port, false));
            }
        }
    }

    let cloned_config = config.clone();
    let fut = join_all(svr_fut).and_then(move |svr_addrs| {
                                             let mut u = Vec::with_capacity(svr_addrs.len());
                                             for (idx, svr_addr) in svr_addrs.into_iter().enumerate() {
                                                 let local_addr =
                                                     SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0);
                                                 let s = UdpSocket::bind(&local_addr)?;
                                                 let svr_cfg = Arc::new(cloned_config.server[idx].clone());
                                                 u.push((Arc::new(Mutex::new(s)), svr_cfg, svr_addr[0]));
                                             }
                                             Ok(u)
                                         })
                               .and_then(move |vec_servers| {
                                             let mut f = Vec::with_capacity(1 + vec_servers.len());
                                             let l = Arc::new(Mutex::new(l));
                                             f.push(handle_l2r(config, l.clone(), vec_servers.clone()));
                                             for (svr, cfg, _) in vec_servers {
                                                 f.push(handle_r2l(l.clone(), svr, cfg))
                                             }
                                             join_all(f)
                                         })
                               .map(|_| ());

    boxed_future(fut)
}

lazy_static! {
    static ref GLOBAL_QUERY_ADDR: Mutex<LruCache<u16, SocketAddr>> = Mutex::new(LruCache::new(1024));
}

fn handle_l2r(config: Arc<Config>,
              l: SharedUdpSocket,
              server: Vec<(SharedUdpSocket, Arc<ServerConfig>, SocketAddr)>)
              -> IoFuture<()> {
    assert!(!server.is_empty());

    let mut server_idx: usize = 0;
    let server = Arc::new(server);

    let fut =
        PacketStream::new(l).for_each(move |(payload, src)| {
            let server = server.clone();
            let config = config.clone();
            futures::lazy(move || {
                              let pkt = Packet::parse(&payload[..]).map_err(|err| {
                                                                   error!("Failed to parse DNS payload, err: {}", err);
                                                                   io::Error::new(io::ErrorKind::Other,
                                                                                  "parse DNS packet failed")
                                                               })?;

                              debug!("DNS QUERY id={} src={} {:?}", pkt.header.id, src, pkt);

                              let (ref socket, ref svr_cfg, svr_addr) = &server[server_idx % server.len()];
                              let (ni, _) = server_idx.overflowing_add(1);
                              server_idx = ni;

                              let mut buf = Vec::new();
                              Address::SocketAddress(config.dns).write_to_buf(&mut buf);

                              buf.extend_from_slice(&payload);

                              let socket = socket.clone();
                              let id = pkt.header.id;
                              encrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf).map(move |send_payload| {
                                                                                             (socket,
                                                                                             *svr_addr,
                                                                                             send_payload,
                                                                                             id)
                                                                                         })
                          }).and_then(move |(socket, svr_addr, send_payload, id)| {
                                                      SendDgramRc::new(socket, send_payload, svr_addr).map(move |_| {
                                                          GLOBAL_QUERY_ADDR.lock().unwrap().insert(id, src);
                                                      })
                                                  })
        });
    boxed_future(fut)
}

fn handle_r2l(l: SharedUdpSocket, r: SharedUdpSocket, svr_cfg: Arc<ServerConfig>) -> IoFuture<()> {
    let fut = PacketStream::new(r).for_each(move |(payload, src)| {
        let l = l.clone();
        let svr_cfg = svr_cfg.clone();
        futures::lazy(move || {
            decrypt_payload(svr_cfg.method(), svr_cfg.key(), &payload)
        }).and_then(move |payload| {
            Address::read_from(Cursor::new(payload))
                .map_err(From::from)
        }).and_then(move |(cur, ..)| {
            let pos = cur.position() as usize;
            let payload = cur.into_inner();

            let pkt = Packet::parse(&payload[pos..]).map_err(|err| {
                error!("Failed to parse DNS payload, err: {}", err);
                io::Error::new(io::ErrorKind::Other, "parse DNS packet failed")
            })?;

            let payload = payload[pos..].to_vec();

            debug!("DNS RESPONSE id={} server={} {:?}", pkt.header.id, src, pkt);

            Ok((pkt.header.id, payload))
        }).and_then(move |(id, payload)| {
            match GLOBAL_QUERY_ADDR.lock().unwrap().remove(&id) {
                Some(cli_addr) => {
                    let f = SendDgramRc::new(l, payload, cli_addr)
                        .map(|_| ());
                    boxed_future(f)
                }
                None => {
                    boxed_future(futures::finished(()))
                }
            }
        })
    });

    boxed_future(fut)
}
