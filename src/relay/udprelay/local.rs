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

use net2::UdpBuilder;

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
    socket: UdpSocket,
}

impl Client {
    /// Resolves server address to SocketAddr
    fn resolve_server_addr(svr_cfg: Rc<ServerConfig>) -> BoxIoFuture<SocketAddr> {
        match svr_cfg.addr() {
            // Return directly if it is a SocketAddr
            &ServerAddr::SocketAddr(ref addr) => boxed_future(futures::finished(addr.clone())),
            // Resolve domain name to SocketAddr
            &ServerAddr::DomainName(ref dname, port) => {
                let fut = DnsResolver::get_instance()
                    .resolve(dname)
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

    /// Handles relay from proxy to client
    ///
    /// Extract actual body from payload
    /// Appends a SOCKS5 UDP Associate header in front of the body, and send it to client
    fn handle_s2c(self, svr_cfg: Rc<ServerConfig>, buf: Vec<u8>, n: usize) -> BoxIoFuture<Client> {
        let Client { assoc, server_picker, servers, socket } = self;

        let fut = futures::lazy(move || {
                let buf = &buf[..n];

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

                // Decrypt payload with cipher
                let mut payload = Vec::with_capacity(buf.len());
                try!(cipher.update(&buf[iv_len..], &mut payload));
                try!(cipher.finalize(&mut payload));

                Ok(payload)
            })
            .and_then(move |payload| {
                // Get Address from the front of payload (ShadowSocks protocol)
                Address::read_from(Cursor::new(payload))
                    .map_err(From::from)
                    .and_then(move |(r, addr)| {

                        let header_len = r.position() as usize;
                        let payload = r.into_inner();
                        let body = &payload[header_len..];

                        trace!("Got packet from {}, payload length {}", addr, body.len());

                        // Append header in front of the actual body (SOCKS5 protocol)
                        let mut reply_body =
                            UdpAssociateHeader::new(0, addr.clone()).write_to(Vec::new()).wait().unwrap();
                        reply_body.extend_from_slice(body);

                        // Get associated client's SocketAddr
                        // We have to know who sent packet to this `addr`
                        let cloned_assoc = assoc.clone();
                        let mut assoc = assoc.borrow_mut();
                        assoc.remove(&addr)
                            .ok_or_else(|| {
                                warn!("Got unassociated packet from server, addr: {:?}", addr);
                                io::Error::new(io::ErrorKind::Other, "unassociated packet")
                            })
                            .map(|client_addr| {
                                info!("UDP ASSOCIATE {} <- {}, payload length {} bytes",
                                      client_addr,
                                      addr,
                                      body.len());
                                (client_addr, cloned_assoc, reply_body)
                            })
                    })
                    .and_then(|(client_addr, assoc, reply_body)| {
                        send_to(socket, reply_body, client_addr).map(move |(socket, _, _)| {
                            Client {
                                assoc: assoc,
                                servers: servers,
                                server_picker: server_picker,
                                socket: socket,
                            }
                        })
                    })
            });

        boxed_future(fut)
    }

    /// Handles relay from client to proxy
    ///
    /// Appends a Address header in front of the packet, and send it to proxy after encryption
    fn handle_c2s(self, buf: Vec<u8>, n: usize, src: SocketAddr) -> BoxIoFuture<Client> {
        let Client { assoc, server_picker, servers, socket } = self;

        let fut = futures::lazy(move || {
                // Extract UDP associate header in the front (SOCKS5 protocol)
                let reader = Cursor::new(buf[..n].to_vec());
                let (reader, header) = try!(UdpAssociateHeader::read_from(reader).wait());

                let header_length = reader.position() as usize;
                Ok((reader.into_inner(), header, header_length))
            })
            .and_then(|(payload, header, header_len)| {
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

                info!("UDP ASSOCIATE {} -> {}, payload length {} bytes",
                      src,
                      assoc_addr,
                      &payload[header_len..].len());

                {
                    // Record association: addr -> SocketAddr (Client)
                    let mut assoc = assoc.borrow_mut();
                    assoc.insert(assoc_addr.clone(), src);
                }
                let svr_cfg = server_picker.borrow_mut().pick_server();

                // Client -> Proxy
                let iv = svr_cfg.method().gen_init_vec();
                let mut cipher = cipher::with_type(svr_cfg.method(),
                                                   svr_cfg.key(),
                                                   &iv[..],
                                                   CryptoMode::Encrypt);

                let payload_buf = Vec::with_capacity(payload.len());
                // Append Address to the front (ShadowSocks protocol)
                assoc_addr.write_to(payload_buf)
                    .and_then(move |mut payload_buf| {
                        payload_buf.extend_from_slice(&payload[header_len..]);
                        Ok(payload_buf)
                    })
                    .and_then(move |payload| -> io::Result<_> {
                        // Encrypt the whole body as payload
                        let mut send_payload = Vec::with_capacity(iv.len() + payload.len());
                        send_payload.extend_from_slice(&iv[..]);
                        try!(cipher.update(&payload[..], &mut send_payload));
                        try!(cipher.finalize(&mut send_payload));
                        Ok((svr_cfg, send_payload))
                    })
                    .map_err(From::from)
                    .and_then(move |(svr_cfg, payload)| {
                        // Select one server
                        Client::resolve_server_addr(svr_cfg.clone()).and_then(move |addr| {
                            {
                                // Record server's address in ServerCache, so we can know which packets
                                // are from proxy servers
                                let mut svrs_ref = servers.borrow_mut();
                                svrs_ref.insert(addr.clone(), svr_cfg.clone());
                            }

                            send_to(socket, payload, addr).map(|(socket, body, len)| {
                                trace!("Body size: {}, sent packet size: {}", body.len(), len);
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
        let Client { assoc, server_picker, servers, socket } = self;

        let fut = recv_from(socket, vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE]).and_then(move |(socket, buf, n, src)| {
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
    let fut = client.handle_once()
        .and_then(|c| handle_client(c));
    boxed_future(fut)
}

fn listen(config: Rc<Config>, l: UdpSocket) -> BoxIoFuture<()> {
    let assoc = Rc::new(RefCell::new(AssociateMap::new(MAXIMUM_ASSOCIATE_MAP_SIZE)));
    let server_picker = Rc::new(RefCell::new(RoundRobin::new(&*config)));
    let servers: Rc<RefCell<ServerCache>> = Rc::new(RefCell::new(ServerCache::new(config.server.len())));

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
pub fn run(config: Rc<Config>, handle: Handle) -> BoxIoFuture<()> {
    let fut = futures::lazy(move || {
            let l = {
                let local_addr = config.local.as_ref().unwrap();
                let udp_builder = match local_addr {
                        &SocketAddr::V4(..) => UdpBuilder::new_v4(),
                        &SocketAddr::V6(..) => UdpBuilder::new_v6(),
                    }
                    .unwrap_or_else(|err| panic!("Failed to create socket, {}", err));

                super::reuse_port(&udp_builder)
                    .and_then(|b| b.reuse_address(true))
                    .unwrap_or_else(|err| panic!("Failed to set reuse {}, {}", local_addr, err));

                info!("ShadowSocks UDP Listening on {}", local_addr);

                try!(udp_builder.bind(local_addr).and_then(|s| UdpSocket::from_socket(s, &handle)))
            };
            Ok((config, l))
        })
        .and_then(move |(config, l)| listen(config, l));

    boxed_future(fut)
}