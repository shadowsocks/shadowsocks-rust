//! UDP relay proxy server

use futures::{self, Future};
use std::cell::RefCell;
use std::io::{self, Cursor};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;

use tokio_core::net::UdpSocket;

use lru_cache::LruCache;

use config::ServerConfig;
use relay::{BoxIoFuture, boxed_future};
use relay::Context;
use relay::dns_resolver::resolve;
use relay::socks5::Address;

use super::{MAXIMUM_ASSOCIATE_MAP_SIZE, MAXIMUM_UDP_PAYLOAD_SIZE};
use super::crypto_io::{decrypt_payload, encrypt_payload};

#[derive(Debug, Clone)]
struct Associate {
    address: Address,
    client_addr: SocketAddr,
}

type AssociateMap = LruCache<SocketAddr, Associate>;

/// Context for handling a UDP packet
pub struct ConnectionContext {
    assoc: Rc<RefCell<AssociateMap>>,
    svr_cfg: Rc<ServerConfig>,
    socket: UdpSocket,
}

impl ConnectionContext {
    /// Handles Client to Remote
    ///
    /// Extract and send the actual request body and associate remote with client
    fn handle_c2s(self, buf: Vec<u8>, n: usize, src: SocketAddr) -> BoxIoFuture<ConnectionContext> {
        let ConnectionContext {
            assoc,
            svr_cfg,
            socket,
        } = self;

        // Client -> Remote
        let fut = futures::lazy(move || {
            let buf = &buf[..n];
            decrypt_payload(svr_cfg.method(), svr_cfg.key(), buf).map(move |b| (b, svr_cfg))
        }).and_then(move |(payload, svr_cfg)| {
            // Read Address in the front (ShadowSocks protocol)
            Address::read_from(Cursor::new(payload))
                .map_err(From::from)
                .and_then(move |(r, addr)| {
                    let header_len = r.position() as usize;
                    let mut payload = r.into_inner();
                    payload.drain(..header_len);
                    let body = payload;

                    info!("UDP ASSOCIATE {} -> {}, payload length {} bytes", src, addr, body.len());

                    let cloned_assoc = assoc.clone();
                    let cloned_addr = addr.clone();
                    ConnectionContext::resolve_remote_addr(addr)
                        .and_then(move |remote_addr| {
                            // Associate client address with remote
                            let mut assoc = cloned_assoc.borrow_mut();
                            assoc.insert(
                                remote_addr,
                                Associate {
                                    address: cloned_addr,
                                    client_addr: src,
                                },
                            );

                            socket.send_dgram(body, remote_addr)
                        })
                        .map(move |(socket, body)| {
                            trace!("Sent body, len: {} bytes", body.len());
                            ConnectionContext {
                                assoc: assoc,
                                svr_cfg: svr_cfg,
                                socket: socket,
                            }
                        })
                })
        });
        boxed_future(fut)
    }

    /// Handle Remote to Client
    ///
    /// Return packet to Client with encryption
    fn handle_s2c(
        self,
        Associate {
            address,
            client_addr,
        }: Associate,
        buf: Vec<u8>,
        n: usize,
    ) -> BoxIoFuture<ConnectionContext> {
        let ConnectionContext {
            assoc,
            svr_cfg,
            socket,
        } = self;

        let buf_len = buf[..n].len();
        info!("UDP ASSOCIATE {} <- {}, payload length {} bytes", client_addr, address, buf_len);

        // Client <- Remote
        // Append Address in front of body (ShadowSocks protocol)
        let cloned_svr_cfg = svr_cfg.clone();
        let fut = address
            .write_to(Cursor::new(Vec::with_capacity(buf_len)))
            .map(move |send_buf| {
                let mut send_buf = send_buf.into_inner();
                send_buf.extend_from_slice(&buf[..n]);
                send_buf
            })
            .and_then(move |send_buf| -> io::Result<_> {
                let svr_cfg = cloned_svr_cfg;
                encrypt_payload(svr_cfg.method(), svr_cfg.key(), &send_buf)
            })
            .and_then(move |final_buf| socket.send_dgram(final_buf, client_addr))
            .map(|(socket, buf)| {
                trace!("Sent body len: {}", buf.len());
                ConnectionContext {
                    assoc: assoc,
                    svr_cfg: svr_cfg,
                    socket: socket,
                }
            });

        boxed_future(fut)
    }

    // Handle one packet
    fn handle_once(self) -> BoxIoFuture<ConnectionContext> {
        let ConnectionContext {
            assoc,
            svr_cfg,
            socket,
        } = self;

        let fut = socket
            .recv_dgram(vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE])
            .and_then(move |(socket, buf, n, src)| {
                let c = ConnectionContext {
                    assoc: assoc.clone(),
                    svr_cfg: svr_cfg,
                    socket: socket,
                };

                let mut assoc = assoc.borrow_mut();
                let fut = match assoc.remove(&src) {
                    None => c.handle_c2s(buf, n, src),
                    Some(cassoc) => c.handle_s2c(cassoc, buf, n),
                };

                Ok(fut)
            })
            .and_then(|fut| fut);

        boxed_future(fut)
    }

    fn resolve_remote_addr(addr: Address) -> BoxIoFuture<SocketAddr> {
        match addr {
            Address::SocketAddress(s) => boxed_future(futures::finished(s)),
            Address::DomainNameAddress(ref dname, port) => {
                let fut = Context::with(|ctx| resolve(dname, ctx.handle()));
                let fut = fut.map(move |sockaddr| match sockaddr {
                    IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                    IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                });
                boxed_future(fut)
            }
        }
    }
}

fn handle_client(c: ConnectionContext) -> BoxIoFuture<()> {
    let fut = c.handle_once().and_then(handle_client);
    boxed_future(fut)
}

fn listen(svr_cfg: Rc<ServerConfig>) -> BoxIoFuture<()> {
    let listen_addr = *svr_cfg.addr().listen_addr();
    info!("ShadowSocks UDP listening on {}", listen_addr);
    let fut = futures::lazy(move || Context::with(|ctx| UdpSocket::bind(&listen_addr, ctx.handle())))
        .and_then(|socket| {
            let c = ConnectionContext {
                assoc: Rc::new(RefCell::new(AssociateMap::new(MAXIMUM_ASSOCIATE_MAP_SIZE))),
                svr_cfg: svr_cfg,
                socket: socket,
            };
            handle_client(c)
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
