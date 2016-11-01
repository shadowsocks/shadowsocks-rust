// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// SOCKS5 UDP Request
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// SOCKS5 UDP Response
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+

// shadowsocks UDP Request (before encrypted)
// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+

// shadowsocks UDP Response (before encrypted)
// +------+----------+----------+----------+
// | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +------+----------+----------+----------+
// |  1   | Variable |    2     | Variable |
// +------+----------+----------+----------+

// shadowsocks UDP Request and Response (after encrypted)
// +-------+--------------+
// |   IV  |    PAYLOAD   |
// +-------+--------------+
// | Fixed |   Variable   |
// +-------+--------------+

//! UDP relay local server

use std::rc::Rc;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Cursor};
use std::cell::RefCell;

use futures::{self, Future};

use tokio_core::reactor::Handle;
use tokio_core::net::UdpSocket;

use lru_cache::LruCache;

use ip::IpAddr;

use config::{Config, ServerConfig, ServerAddr};
use relay::{BoxIoFuture, boxed_future};
use relay::loadbalancing::server::{LoadBalancer, RoundRobin};
use relay::dns_resolver::DnsResolver;
use relay::socks5::{Address, UdpAssociateHeader};
use crypto::cipher::{self, Cipher};
use crypto::CryptoMode;

use super::{MAXIMUM_ASSOCIATE_MAP_SIZE, MAXIMUM_UDP_PAYLOAD_SIZE};
use super::{send_to, recv_from};

type AssociateMap = LruCache<Address, SocketAddr>;
type ServerCache = LruCache<SocketAddr, Rc<ServerConfig>>;

struct Client {
    assoc: Rc<RefCell<AssociateMap>>,
    server_picker: Rc<RefCell<RoundRobin>>,
    servers: Rc<RefCell<ServerCache>>,
    dns_resolver: DnsResolver,
    socket: UdpSocket,
}

impl Client {
    fn handle_once(self) -> BoxIoFuture<Client> {
        let Client { assoc, server_picker, servers, dns_resolver, socket } = self;

        let fut = recv_from(socket, vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE])
            .and_then(move |(socket, buf, n, src)| {
                let buf = &buf[..n];

                let cloned_servers = servers.clone();
                let cloned_assoc = assoc.clone();

                let fut = match servers.borrow_mut().get_mut(&src) {
                    Some(svr_cfg) => {
                        // Proxy -> Client
                        trace!("Got packet from server {}, length {}",
                               svr_cfg.addr(),
                               buf.len());

                        let iv_len = svr_cfg.method().iv_size();
                        if buf.len() < iv_len {
                            error!("Invalid ShadowSocks UDP packet, expected IV length {}, packet length {}",
                                   iv_len,
                                   buf.len());
                            let err = io::Error::new(io::ErrorKind::Other, "early eof");
                            return Err(err);
                        }

                        let iv = &buf[..iv_len];
                        let mut cipher = cipher::with_type(svr_cfg.method(), svr_cfg.key(), iv, CryptoMode::Decrypt);

                        let mut payload = Vec::with_capacity(buf.len());
                        try!(cipher.update(&buf[iv_len..], &mut payload));
                        try!(cipher.finalize(&mut payload));

                        let reader = Cursor::new(payload);
                        let fut = Address::read_from(reader).map_err(From::from).and_then(move |(r, addr)| {

                            let header_len = r.position() as usize;
                            let payload = r.into_inner();
                            let body = &payload[header_len..];

                            trace!("Got packet from {}, payload length {}", addr, body.len());

                            // Will always success
                            let mut reply_body =
                                UdpAssociateHeader::new(0, addr.clone()).write_to(Vec::new()).wait().unwrap();
                            reply_body.extend_from_slice(body);

                            let mut assoc = assoc.borrow_mut();
                            match assoc.remove(&addr) {
                                None => {
                                    warn!("Got unassociated packet from server, addr: {:?}", addr);
                                    let err = io::Error::new(io::ErrorKind::Other, "unassociated packet");
                                    boxed_future(futures::failed(err))
                                }
                                Some(client_addr) => {
                                    info!("UDP ASSOCIATE {} <- {}, payload length {} bytes",
                                          client_addr,
                                          addr,
                                          body.len());

                                    let fut = send_to(socket, reply_body, client_addr).map(move |(socket, _, _)| {
                                        Client {
                                            assoc: cloned_assoc,
                                            servers: cloned_servers,
                                            dns_resolver: dns_resolver,
                                            server_picker: server_picker,
                                            socket: socket,
                                        }
                                    });

                                    boxed_future(fut)
                                }
                            }
                        });

                        boxed_future(fut)
                    }

                    None => {
                        // Client -> Proxy

                        let reader = Cursor::new(buf.to_vec());
                        let fut = UdpAssociateHeader::read_from(reader)
                            .map_err(From::from)
                            .and_then(move |(r, header)| {

                                if header.frag != 0 {
                                    warn!("Does not support UDP fragment, got header {:?}", header);
                                    let err = io::Error::new(io::ErrorKind::Other, "Not supported UDP fragment");
                                    return boxed_future(futures::failed(err));
                                }

                                let header_len = r.position() as usize;
                                let payload = r.into_inner();
                                let assoc_addr = header.address;

                                info!("UDP ASSOCIATE {} -> {}, payload length {} bytes",
                                      src,
                                      assoc_addr,
                                      &payload[header_len..].len());

                                // If we have recorded address, then it is a return packet from server
                                // Proxy -> Client
                                let mut assoc = assoc.borrow_mut();

                                let svr_cfg = server_picker.borrow_mut().pick_server();
                                assoc.insert(assoc_addr.clone(), src);

                                // Client -> Proxy
                                let fut = futures::lazy(move || {
                                        let iv = svr_cfg.method().gen_init_vec();
                                        let mut cipher = cipher::with_type(svr_cfg.method(),
                                                                           svr_cfg.key(),
                                                                           &iv[..],
                                                                           CryptoMode::Encrypt);

                                        let payload_buf = Vec::with_capacity(payload.len());
                                        assoc_addr.write_to(payload_buf)
                                            .and_then(move |mut payload_buf| {
                                                payload_buf.extend_from_slice(&payload[header_len..]);
                                                Ok(payload_buf)
                                            })
                                            .and_then(move |payload| -> io::Result<_> {
                                                let mut send_payload = Vec::with_capacity(iv.len() + payload.len());
                                                send_payload.extend_from_slice(&iv[..]);
                                                try!(cipher.update(&payload[..], &mut send_payload));
                                                try!(cipher.finalize(&mut send_payload));
                                                Ok((svr_cfg, send_payload))
                                            })
                                    })
                                    .map_err(From::from)
                                    .and_then(move |(svr_cfg, payload)| {
                                        UdpRelayLocal::resolve_server_addr(svr_cfg.clone(), dns_resolver.clone())
                                            .and_then(move |addr| {
                                                // And we have to know the proxy servers' addresses
                                                let servers = cloned_servers.clone();
                                                let mut svrs_ref = cloned_servers.borrow_mut();
                                                svrs_ref.insert(addr.clone(), svr_cfg.clone());

                                                let fut = send_to(socket, payload, addr).map(|(socket, body, len)| {
                                                    trace!("Body size: {}, sent packet size: {}", body.len(), len);
                                                    Client {
                                                        assoc: cloned_assoc,
                                                        server_picker: server_picker,
                                                        servers: servers,
                                                        dns_resolver: dns_resolver,
                                                        socket: socket,
                                                    }
                                                });

                                                boxed_future(fut)
                                            })
                                    });
                                boxed_future(fut)
                            });

                        boxed_future(fut)
                    }
                };

                Ok(fut)
            })
            .and_then(|fut| fut);

        boxed_future(fut)
    }
}

/// UDP relay local server
pub struct UdpRelayLocal;

impl UdpRelayLocal {
    fn resolve_server_addr(svr_cfg: Rc<ServerConfig>, dns_resolver: DnsResolver) -> BoxIoFuture<SocketAddr> {
        match svr_cfg.addr() {
            &ServerAddr::SocketAddr(ref addr) => boxed_future(futures::finished(addr.clone())),
            &ServerAddr::DomainName(ref dname, port) => {
                let fut = dns_resolver.resolve(dname)
                    .map(move |sockaddr| {
                        match sockaddr {
                            IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                            IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, 0)),
                        }
                    });
                boxed_future(fut)
            }
        }
    }

    fn handle_client(client: Client) -> BoxIoFuture<()> {
        let fut = client.handle_once()
            .and_then(|c| UdpRelayLocal::handle_client(c));
        boxed_future(fut)
    }

    fn run_server(config: Rc<Config>, l: UdpSocket, dns_resolver: DnsResolver) -> BoxIoFuture<()> {
        let assoc = Rc::new(RefCell::new(AssociateMap::new(MAXIMUM_ASSOCIATE_MAP_SIZE)));
        let server_picker = Rc::new(RefCell::new(RoundRobin::new(&*config)));
        let servers: Rc<RefCell<ServerCache>> = Rc::new(RefCell::new(ServerCache::new(config.server.len())));

        let c = Client {
            assoc: assoc,
            server_picker: server_picker,
            servers: servers,
            dns_resolver: dns_resolver,
            socket: l,
        };

        boxed_future(UdpRelayLocal::handle_client(c))
    }

    /// Starts a UDP local server
    pub fn run(config: Rc<Config>, handle: Handle, dns_resolver: DnsResolver) -> BoxIoFuture<()> {
        let fut = futures::lazy(move || {
                let l = {
                    let local_addr = config.local.as_ref().unwrap();
                    info!("ShadowSocks UDP Listening on {}", local_addr);
                    try!(UdpSocket::bind(local_addr, &handle))
                };
                Ok((config, l))
            })
            .and_then(move |(config, l)| UdpRelayLocal::run_server(config, l, dns_resolver));

        boxed_future(fut)
    }
}