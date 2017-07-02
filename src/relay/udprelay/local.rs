//! UDP relay local server

use std::rc::Rc;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Cursor};
use std::cell::RefCell;
use std::net::IpAddr;

use futures::{self, Future};

use tokio_core::net::UdpSocket;

use lru_cache::LruCache;

use config::{ServerConfig, ServerAddr};
use relay::{BoxIoFuture, boxed_future};
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};
use relay::dns_resolver::resolve;
use relay::socks5::{Address, UdpAssociateHeader};
use relay::Context;

use super::{MAXIMUM_ASSOCIATE_MAP_SIZE, MAXIMUM_UDP_PAYLOAD_SIZE};
use super::crypto_io::{encrypt_payload, decrypt_payload};

type AssociateMap = LruCache<Address, SocketAddr>;
type ServerCache = LruCache<SocketAddr, Rc<ServerConfig>>;

struct Client {
    assoc: Rc<RefCell<AssociateMap>>,
    server_picker: Rc<RefCell<RoundRobin>>,
    servers: Rc<RefCell<ServerCache>>,
    socket: UdpSocket,
}

impl Client {
    /// Resolves server address to SocketAddr
    fn resolve_server_addr(svr_cfg: Rc<ServerConfig>) -> BoxIoFuture<SocketAddr> {
        match *svr_cfg.addr() {
            // Return directly if it is a SocketAddr
            ServerAddr::SocketAddr(ref addr) => boxed_future(futures::finished(*addr)),
            // Resolve domain name to SocketAddr
            ServerAddr::DomainName(ref dname, port) => {
                let fut = Context::with(|ctx| resolve(dname, ctx.handle()));
                let fut = fut.map(move |sockaddr| match sockaddr {
                    IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                    IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                });
                boxed_future(fut)
            }
        }
    }

    /// Handles relay from proxy to client
    ///
    /// Extract actual body from payload
    /// Appends a SOCKS5 UDP Associate header in front of the body, and send it to client
    fn handle_s2c(self, svr_cfg: Rc<ServerConfig>, buf: Vec<u8>, n: usize) -> BoxIoFuture<Client> {
        let Client {
            assoc,
            server_picker,
            servers,
            socket,
        } = self;

        let fut = futures::lazy(move || {
            let buf = &buf[..n];

            trace!(
                "Got packet from server {}, length {}",
                svr_cfg.addr(),
                buf.len()
            );

            decrypt_payload(svr_cfg.method(), svr_cfg.key(), buf)
        }).and_then(move |payload| {
            // Get Address from the front of payload (ShadowSocks protocol)
            Address::read_from(Cursor::new(payload))
                .map_err(From::from)
                .and_then(move |(r, addr)| {

                    let header_len = r.position() as usize;
                    let payload = r.into_inner();
                    let body = &payload[header_len..];

                    trace!("Got packet from {}, payload length {}", addr, body.len());

                    // Append header in front of the actual body (SOCKS5 protocol)
                    let buf = Cursor::new(Vec::new());
                    let mut reply_body = UdpAssociateHeader::new(0, addr.clone())
                        .write_to(buf)
                        .wait()
                        .unwrap()
                        .into_inner();
                    reply_body.extend_from_slice(body);

                    // Get associated client's SocketAddr
                    // We have to know who sent packet to this `addr`
                    let cloned_assoc = assoc.clone();
                    let mut assoc = assoc.borrow_mut();
                    assoc
                        .remove(&addr)
                        .ok_or_else(|| {
                            warn!("Got unassociated packet from server, addr: {:?}", addr);
                            io::Error::new(io::ErrorKind::Other, "unassociated packet")
                        })
                        .map(|client_addr| {
                            info!(
                                "UDP ASSOCIATE {} <- {}, payload length {} bytes",
                                client_addr,
                                addr,
                                body.len()
                            );
                            (client_addr, cloned_assoc, reply_body)
                        })
                })
                .and_then(|(client_addr, assoc, reply_body)| {
                    socket.send_dgram(reply_body, client_addr).map(
                        move |(socket,
                               _)| {
                            Client {
                                assoc: assoc,
                                servers: servers,
                                server_picker: server_picker,
                                socket: socket,
                            }
                        },
                    )
                })
        });

        boxed_future(fut)
    }

    /// Handles relay from client to proxy
    ///
    /// Appends a Address header in front of the packet, and send it to proxy after encryption
    fn handle_c2s(self, buf: Vec<u8>, n: usize, src: SocketAddr) -> BoxIoFuture<Client> {
        let Client {
            assoc,
            server_picker,
            servers,
            socket,
        } = self;

        let fut = futures::lazy(move || {
            // Extract UDP associate header in the front (SOCKS5 protocol)
            let reader = Cursor::new(buf[..n].to_vec());
            let (reader, header) = try!(UdpAssociateHeader::read_from(reader).wait());

            let header_length = reader.position() as usize;
            Ok((reader.into_inner(), header, header_length))
        }).and_then(|(payload, header, header_len)| {
            // ShadowSocks does not support UDP fragment
            // Drop the packet directly according to SOCKS5's RFC
            if header.frag != 0x00 {
                warn!("Does not support UDP fragment, got header {:?}", header);
                let err = io::Error::new(io::ErrorKind::Other, "Not supported UDP fragment");
                Err(err)
            } else {
                Ok((payload, header, header_len))
            }
        })
            .and_then(move |(payload, header, header_len)| {
                let assoc_addr = header.address;

                info!(
                    "UDP ASSOCIATE {} -> {}, payload length {} bytes",
                    src,
                    assoc_addr,
                    &payload[header_len..].len()
                );

                {
                    // Record association: addr -> SocketAddr (Client)
                    let mut assoc = assoc.borrow_mut();
                    assoc.insert(assoc_addr.clone(), src);
                }
                let svr_cfg = server_picker.borrow_mut().pick_server();

                // Client -> Proxy
                // Append Address to the front (ShadowSocks protocol)
                let buf = Cursor::new(Vec::with_capacity(payload.len()));
                assoc_addr
                    .write_to(buf)
                    .and_then(move |payload_buf| {
                        let mut payload_buf = payload_buf.into_inner();
                        payload_buf.extend_from_slice(&payload[header_len..]);
                        Ok(payload_buf)
                    })
                    .and_then(move |payload| -> io::Result<_> {
                        // Encrypt the whole body as payload
                        encrypt_payload(svr_cfg.method(), svr_cfg.key(), &payload).map(move |b| (svr_cfg, b))
                    })
                    .map_err(From::from)
                    .and_then(move |(svr_cfg, payload)| {
                        // Select one server
                        Client::resolve_server_addr(svr_cfg.clone()).and_then(move |addr| {
                            {
                                // Record server's address in ServerCache, so we can know which packets
                                // are from proxy servers
                                let mut svrs_ref = servers.borrow_mut();
                                svrs_ref.insert(addr, svr_cfg.clone());
                            }

                            socket.send_dgram(payload, addr).map(|(socket, body)| {
                                trace!("Sent body, size: {}", body.len());
                                Client {
                                    assoc: assoc,
                                    server_picker: server_picker,
                                    servers: servers,
                                    socket: socket,
                                }
                            })
                        })
                    })
            });

        boxed_future(fut)
    }

    /// Handle Client after `recv_from`
    fn handle_once(self) -> BoxIoFuture<Client> {
        let Client {
            assoc,
            server_picker,
            servers,
            socket,
        } = self;

        let fut = socket
            .recv_dgram(vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE])
            .and_then(move |(socket, buf, n, src)| {
                // Reassemble Client
                let c = Client {
                    assoc: assoc,
                    server_picker: server_picker,
                    servers: servers.clone(),
                    socket: socket,
                };

                let mut servers = servers.borrow_mut();
                match servers.get_mut(&src) {
                    Some(svr_cfg) => c.handle_s2c(svr_cfg.clone(), buf, n),
                    None => c.handle_c2s(buf, n, src),
                }
            });

        boxed_future(fut)
    }
}

// Recursive method for handling clients
// Handle one by one
fn handle_client(client: Client) -> BoxIoFuture<()> {
    let fut = client.handle_once().and_then(handle_client);
    boxed_future(fut)
}

fn listen(l: UdpSocket) -> BoxIoFuture<()> {
    let assoc = Rc::new(RefCell::new(AssociateMap::new(MAXIMUM_ASSOCIATE_MAP_SIZE)));

    let (server_picker, servers) = Context::with(|ctx| {
        let config = ctx.config();
        let server_picker = Rc::new(RefCell::new(RoundRobin::new(&*config)));
        let servers = Rc::new(RefCell::new(ServerCache::new(config.server.len())));
        (server_picker, servers)
    });


    let c = Client {
        assoc: assoc,
        server_picker: server_picker,
        servers: servers,
        socket: l,
    };

    // Starts to handle all connections after initialization
    handle_client(c)
}

/// Starts a UDP local server
pub fn run() -> BoxIoFuture<()> {
    let fut = futures::lazy(|| {
        Context::with(|ctx| {
            let local_addr = ctx.config().local.as_ref().unwrap();
            info!("ShadowSocks UDP Listening on {}", local_addr);

            UdpSocket::bind(local_addr, ctx.handle())
        })
    }).and_then(|l| listen(l));


    boxed_future(fut)
}
