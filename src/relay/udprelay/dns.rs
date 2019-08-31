//! UDP DNS relay

use std::{
    io::{self, Cursor},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use dns_parser::Packet;
use futures::{self, future::join_all, stream::futures_unordered, Future, Stream};
use log::{error, info, trace};
use tokio::{self, net::UdpSocket};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    PacketStream,
    SendDgramRc,
    SharedUdpSocket,
};
use crate::{
    config::{ServerAddr, ServerConfig},
    context::SharedContext,
    relay::{dns_resolver::resolve, socks5::Address},
};

/// Starts a UDP DNS server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = *context.config().local.as_ref().unwrap();

    let listener = UdpSocket::bind(&local_addr)?;
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
        let s = UdpSocket::bind(&local_addr)?;
        let svr_cfg = Arc::new(svr.clone());
    }

    let mut svr_fut = Vec::with_capacity(context.config().server.len());
    for svr in &context.config().server {
        match *svr.addr() {
            ServerAddr::SocketAddr(ref addr) => {
                svr_fut.push(boxed_future(futures::finished::<_, io::Error>(vec![*addr])));
            }
            ServerAddr::DomainName(ref dom, ref port) => {
                svr_fut.push(boxed_future(resolve(context.clone(), &*dom, *port, false)));
            }
        }
    }

    let cloned_context = context.clone();
    join_all(svr_fut)
        .and_then(move |svr_addrs| {
            let mut u = Vec::with_capacity(svr_addrs.len());
            for (idx, svr_addr) in svr_addrs.into_iter().enumerate() {
                let local_addr = SocketAddr::new(IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)), 0);
                let s = UdpSocket::bind(&local_addr)?;
                let svr_cfg = Arc::new(cloned_context.config().server[idx].clone());
                u.push((Arc::new(Mutex::new(s)), svr_cfg, svr_addr[0]));
            }
            Ok(u)
        })
        .and_then(move |vec_servers| {
            let mut f = Vec::with_capacity(1 + vec_servers.len());
            let l = Arc::new(Mutex::new(l));
            f.push(boxed_future(handle_l2r(
                context.clone(),
                l.clone(),
                vec_servers.clone(),
            )));
            for (svr, cfg, _) in vec_servers {
                f.push(boxed_future(handle_r2l(context.clone(), l.clone(), svr, cfg)))
            }
            futures_unordered(f).into_future().then(|res| match res {
                Ok(..) => {
                    error!("One of DNS servers exited unexpectly without error");
                    let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
                    Err(err)
                }
                Err((err, ..)) => {
                    error!("One of DNS servers exited unexpectly with error {}", err);
                    Err(err)
                }
            })
        })
}

async fn handle_l2r(
    context: SharedContext,
    l: SharedUdpSocket,
    server: Vec<(SharedUdpSocket, Arc<ServerConfig>, SocketAddr)>,
) -> io::Result<()> {
    assert!(!server.is_empty());

    let mut server_idx: usize = 0;
    let server = Arc::new(server);

    PacketStream::new(l).for_each(move |(payload, src)| {
        let server = server.clone();
        let context = context.clone();
        let context2 = context.clone();
        let pkt_fut = futures::lazy(move || {
            let pkt = Packet::parse(&payload[..]).map_err(|err| {
                error!("Failed to parse DNS payload, err: {}", err);
                io::Error::new(io::ErrorKind::Other, "parse DNS packet failed")
            })?;

            let (ref socket, ref svr_cfg, svr_addr) = server[server_idx % server.len()];
            let (ni, _) = server_idx.overflowing_add(1);
            server_idx = ni;

            trace!("DNS {} -> {} packet: {:?}", src, svr_cfg.addr(), pkt);

            let mut buf = Vec::new();
            Address::SocketAddress(context.config().get_remote_dns()).write_to_buf(&mut buf);

            buf.extend_from_slice(&payload);

            let socket = socket.clone();
            let id = pkt.header.id;
            encrypt_payload(svr_cfg.method(), svr_cfg.key(), &buf)
                .map(move |send_payload| (socket, svr_addr, send_payload, id))
        })
        .and_then(move |(socket, svr_addr, send_payload, id)| {
            SendDgramRc::new(socket, send_payload, svr_addr).map(move |_| {
                context2.dns_query_cache().insert(id, (src, Instant::now()));
            })
        });
        tokio::spawn(pkt_fut.then(|res| match res {
            Ok(..) => Ok(()),
            Err(err) => {
                error!("Failed to handle local -> remote packet, err: {}", err);
                Err(())
            }
        }));

        Ok(())
    })
}

fn handle_r2l(
    context: SharedContext,
    l: SharedUdpSocket,
    r: SharedUdpSocket,
    svr_cfg: Arc<ServerConfig>,
) -> impl Future<Item = (), Error = io::Error> + Send {
    PacketStream::new(r).for_each(move |(payload, src)| {
        let l = l.clone();
        let svr_cfg = svr_cfg.clone();
        let context = context.clone();
        let pkt_fut = futures::lazy(move || decrypt_payload(svr_cfg.method(), svr_cfg.key(), &payload))
            .and_then(move |payload| Address::read_from(Cursor::new(payload)).map_err(From::from))
            .and_then(move |(cur, ..)| {
                let pos = cur.position() as usize;
                let payload = cur.into_inner();

                let pkt = Packet::parse(&payload[pos..]).map_err(|err| {
                    error!("Failed to parse DNS payload, err: {}", err);
                    io::Error::new(io::ErrorKind::Other, "parse DNS packet failed")
                })?;

                let payload = payload[pos..].to_vec();

                let mut cache = context.dns_query_cache();
                match cache.remove(&pkt.header.id) {
                    Some((cli_addr, start_time)) => {
                        trace!(
                            "DNS {} <- {} elapsed: {:?} packet: {:?}",
                            cli_addr,
                            src,
                            Instant::now() - start_time,
                            pkt,
                        );

                        Ok(Some((cli_addr, payload)))
                    }
                    None => {
                        error!(
                            "DNS received packet id={} opcode={:?} but found no local endpoint",
                            pkt.header.id, pkt.header.opcode
                        );
                        Ok(None)
                    }
                }
            })
            .and_then(move |opt| match opt {
                Some((cli_addr, payload)) => {
                    let f = SendDgramRc::new(l, payload, cli_addr).map(|_| ());
                    boxed_future(f)
                }
                None => boxed_future(futures::finished(())),
            });

        tokio::spawn(pkt_fut.then(|res| match res {
            Ok(..) => Ok(()),
            Err(err) => {
                error!("Failed to handle local <- remote packet, err: {}", err);
                Err(())
            }
        }));

        Ok(())
    })
}
