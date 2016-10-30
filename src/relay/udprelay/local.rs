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

use std::rc::Rc;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Cursor};
use std::cell::RefCell;
use std::mem;

use futures::{self, Future, Poll, Async};
use futures::stream::Stream;

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

use super::{MAXIMUM_UDP_PAYLOAD_SIZE, MAXIMUM_ASSOCIATE_MAP_SIZE};

type AssociateMap = LruCache<Address, SocketAddr>;
type ServerCache = LruCache<SocketAddr, Rc<ServerConfig>>;

#[derive(Clone)]
pub struct UdpRelayLocal;

impl UdpRelayLocal {
    fn resolve_server_addr(svr_cfg: Rc<ServerConfig>, dns_resolver: DnsResolver) -> BoxIoFuture<SocketAddr> {
        match svr_cfg.addr {
            ServerAddr::SocketAddr(ref addr) => boxed_future(futures::finished(addr.clone())),
            ServerAddr::DomainName(ref dname, port) => {
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

    fn run_server(config: Rc<Config>, l: UdpSocket, handle: Handle, dns_resolver: DnsResolver) -> BoxIoFuture<()> {
        let fut = futures::lazy(move || {
            let assoc = Rc::new(RefCell::new(AssociateMap::new(MAXIMUM_ASSOCIATE_MAP_SIZE)));
            let server_picker = Rc::new(RefCell::new(RoundRobin::new(&*config)));
            let servers: Rc<RefCell<ServerCache>> = Rc::new(RefCell::new(ServerCache::new(config.server.len())));

            let cloned_handle = handle.clone();
            udp_incoming(l).for_each(move |(buf, addr)| {
                let server_picker = server_picker.clone();
                let dns_resolver = dns_resolver.clone();
                let handle = handle.clone();
                let assoc = assoc.clone();
                let servers_clone = servers.clone();
                let config = config.clone();

                match servers.borrow_mut().get_mut(&addr) {
                    Some(svr_cfg) => {
                        // Proxy -> Client

                        trace!("Got packet from server {}, length {}",
                               svr_cfg.addr,
                               buf.len());

                        let iv_len = svr_cfg.method.iv_size();
                        if buf.len() < iv_len {
                            error!("Invalid ShadowSocks UDP packet, expected IV length {}, packet length {}",
                                   iv_len,
                                   buf.len());
                            let err = io::Error::new(io::ErrorKind::Other, "early eof");
                            return Err(err);
                        }

                        let iv = &buf[..iv_len];
                        let mut cipher = cipher::with_type(svr_cfg.method,
                                                           svr_cfg.password.as_bytes(),
                                                           iv,
                                                           CryptoMode::Decrypt);

                        let mut payload = Vec::with_capacity(buf.len());
                        try!(cipher.update(&buf[iv_len..], &mut payload));
                        try!(cipher.finalize(&mut payload));

                        let reader = Cursor::new(payload);
                        let fut = Address::read_from(reader).map_err(From::from).and_then(move |(r, addr)| {
                            let header_len = r.position() as usize;
                            let mut payload = r.into_inner();
                            payload.drain(..header_len);
                            let body = payload;

                            trace!("Got packet from {}, payload length {}", addr, body.len());
                            let mut assoc = assoc.borrow_mut();
                            match assoc.remove(&addr) {
                                None => {
                                    warn!("Got unassociated packet from server, addr: {:?}", addr);
                                    let err = io::Error::new(io::ErrorKind::Other, "unassociated packet");
                                    boxed_future(futures::failed(err))
                                }
                                Some(client_addr) => {
                                    let fut = futures::lazy(move || {
                                            let local_addr = config.local.as_ref().unwrap();
                                            UdpSocket::bind(local_addr, &handle)
                                        })
                                        .and_then(move |socket| send_to(socket, body, client_addr))
                                        .map(|(_, body, len)| {
                                            trace!("Body size: {}, sent packet size: {}", body.len(), len);
                                        });
                                    boxed_future(fut)
                                }
                            }
                        });

                        cloned_handle.spawn(fut.map_err(|err| {
                            error!("Failed to handle client: {}", err);
                        }));
                    }

                    None => {
                        // Client -> Proxy

                        let reader = Cursor::new(buf);
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

                                // If we have recorded address, then it is a return packet from server
                                // Proxy -> Client
                                let mut assoc = assoc.borrow_mut();

                                let svr_cfg = server_picker.borrow_mut().pick_server();
                                assoc.insert(assoc_addr.clone(), addr);

                                // Client -> Proxy
                                let fut = futures::lazy(move || {
                                        let iv = svr_cfg.method.gen_init_vec();
                                        let mut cipher = cipher::with_type(svr_cfg.method,
                                                                           svr_cfg.password.as_bytes(),
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
                                        UdpRelayLocal::resolve_server_addr(svr_cfg.clone(), dns_resolver)
                                            .and_then(move |addr| {
                                                // And we have to know the proxy servers' addresses
                                                let mut servers = servers_clone.borrow_mut();
                                                servers.insert(addr.clone(), svr_cfg.clone());

                                                let fut = futures::lazy(move || {
                                                        let local_addr = config.local.as_ref().unwrap();
                                                        UdpSocket::bind(local_addr, &handle)
                                                    })
                                                    .and_then(move |socket| send_to(socket, payload, addr))
                                                    .map(|(_, body, len)| {
                                                        trace!("Body size: {}, sent packet size: {}", body.len(), len);
                                                    });
                                                boxed_future(fut)
                                            })
                                    });
                                boxed_future(fut)
                            });

                        cloned_handle.spawn(fut.map_err(|err| {
                            error!("Failed to handle client: {}", err);
                        }));
                    }
                }
                Ok(())
            })
        });

        boxed_future(fut)
    }

    pub fn run(config: Rc<Config>, handle: Handle, dns_resolver: DnsResolver) -> BoxIoFuture<()> {
        let fut = futures::lazy(move || {
                let l = {
                    let local_addr = config.local.as_ref().unwrap();
                    info!("ShadowSocks UDP Listening on {}", local_addr);
                    try!(UdpSocket::bind(local_addr, &handle))
                };
                Ok((config, l, handle))
            })
            .and_then(move |(config, l, handle)| UdpRelayLocal::run_server(config, l, handle, dns_resolver));

        boxed_future(fut)
    }
}

struct Incoming {
    socket: UdpSocket,
}

impl Stream for Incoming {
    type Item = (Vec<u8>, SocketAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.socket.poll_read().is_not_ready() {
            return Ok(Async::NotReady);
        }

        let mut buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        match self.socket.recv_from(&mut buf) {
            Ok((n, addr)) => Ok(Some((buf[..n].to_vec(), addr)).into()),
            Err(err) => Err(err),
        }
    }
}

fn udp_incoming(socket: UdpSocket) -> Incoming {
    Incoming { socket: socket }
}

enum SendToUdpSocket<B: AsRef<[u8]>> {
    Pending {
        socket: UdpSocket,
        buf: B,
        target_addr: SocketAddr,
    },
    Empty,
}

impl<B: AsRef<[u8]>> Future for SendToUdpSocket<B> {
    type Item = (UdpSocket, B, usize);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let length = match self {
            &mut SendToUdpSocket::Empty => panic!("poll after SendToUdpSocket is finished"),
            &mut SendToUdpSocket::Pending { ref socket, ref buf, ref target_addr } => {
                if socket.poll_write().is_not_ready() {
                    return Ok(Async::NotReady);
                }

                try_nb!(socket.send_to(buf.as_ref(), target_addr))
            }
        };

        match mem::replace(self, SendToUdpSocket::Empty) {
            SendToUdpSocket::Pending { socket, buf, .. } => Ok((socket, buf, length).into()),
            SendToUdpSocket::Empty => unreachable!(),
        }
    }
}

fn send_to<B: AsRef<[u8]>>(socket: UdpSocket, buf: B, target: SocketAddr) -> SendToUdpSocket<B> {
    SendToUdpSocket::Pending {
        socket: socket,
        buf: buf,
        target_addr: target,
    }
}