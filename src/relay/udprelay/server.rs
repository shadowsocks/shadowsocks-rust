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

//! UDP relay proxy server

use std::rc::Rc;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Cursor};
use std::cell::RefCell;

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::reactor::Handle;
use tokio_core::net::UdpSocket;

use lru_cache::LruCache;

use ip::IpAddr;

use config::{Config, ServerConfig};
use relay::{BoxIoFuture, boxed_future};
use relay::dns_resolver::DnsResolver;
use relay::socks5::Address;
use crypto::cipher::{self, Cipher};
use crypto::CryptoMode;

use super::MAXIMUM_ASSOCIATE_MAP_SIZE;
use super::{send_to, udp_incoming};

#[derive(Debug, Clone)]
struct Associate {
    address: Address,
    client_addr: SocketAddr,
}

type AssociateMap = LruCache<SocketAddr, Associate>;

/// UDP relay proxy server
pub struct UdpRelayServer;

impl UdpRelayServer {
    fn resolve_remote_addr(addr: Address, dns_resolver: DnsResolver) -> BoxIoFuture<SocketAddr> {
        match addr {
            Address::SocketAddress(s) => boxed_future(futures::finished(s)),
            Address::DomainNameAddress(ref dname, port) => {
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

    fn run_server(svr_cfg: Rc<ServerConfig>, handle: Handle, dns_resolver: DnsResolver) -> BoxIoFuture<()> {
        let c_svr_cfg = svr_cfg.clone();
        let c_handle = handle.clone();
        let fut = futures::lazy(move || UdpSocket::bind(c_svr_cfg.addr().listen_addr(), &c_handle))
            .and_then(move |l| {
                let assoc = Rc::new(RefCell::new(AssociateMap::new(MAXIMUM_ASSOCIATE_MAP_SIZE)));

                udp_incoming(l).for_each(move |(mut buf, conn_addr)| {
                    let dns_resolver = dns_resolver.clone();
                    let assoc_clone = assoc.clone();
                    let handle = handle.clone();
                    let cloned_handle = handle.clone();
                    let svr_cfg = svr_cfg.clone();
                    let cloned_conn_addr = conn_addr.clone();

                    match assoc.borrow_mut().remove(&conn_addr) {
                        None => {
                            // Client -> Remote
                            let iv_len = svr_cfg.method().iv_size();
                            if buf.len() < iv_len {
                                error!("Invalid ShadowSocks UDP packet, expected IV length {}, packet length {}",
                                       iv_len,
                                       buf.len());
                                let err = io::Error::new(io::ErrorKind::Other, "early eof");
                                return Err(err);
                            }

                            let iv = &buf[..iv_len];
                            let mut cipher =
                                cipher::with_type(svr_cfg.method(), svr_cfg.key(), iv, CryptoMode::Decrypt);

                            let mut payload = Vec::with_capacity(buf.len());
                            try!(cipher.update(&buf[iv_len..], &mut payload));
                            try!(cipher.finalize(&mut payload));

                            let reader = Cursor::new(payload);
                            let fut = Address::read_from(reader).map_err(From::from).and_then(move |(r, addr)| {
                                let header_len = r.position() as usize;
                                let mut payload = r.into_inner();
                                payload.drain(..header_len);
                                let body = payload;

                                trace!("Got packet to {}, payload length {}", addr, body.len());

                                let cloned_addr = addr.clone();
                                UdpRelayServer::resolve_remote_addr(addr, dns_resolver)
                                    .and_then(move |remote_addr| {
                                        // Record association
                                        let mut assoc = assoc_clone.borrow_mut();
                                        assoc.insert(remote_addr.clone(),
                                                     Associate {
                                                         address: cloned_addr,
                                                         client_addr: cloned_conn_addr,
                                                     });

                                        let svr_addr = svr_cfg.addr().listen_addr();
                                        let l = try!(UdpSocket::bind(svr_addr, &handle));
                                        Ok((l, remote_addr))
                                    })
                                    .and_then(move |(l, raddr)| send_to(l, body, raddr))
                                    .map(|_| ())
                            });

                            cloned_handle.spawn(fut.map_err(|err| {
                                error!("Failed to handle client: {}", err);
                            }));
                        }
                        Some(Associate { address, client_addr }) => {
                            // Client <- Remote
                            let mut iv = svr_cfg.method().gen_init_vec();
                            let mut cipher = cipher::with_type(svr_cfg.method(),
                                                               svr_cfg.key(),
                                                               &iv[..],
                                                               CryptoMode::Encrypt);

                            let fut = address.write_to(Vec::new())
                                .map(move |mut send_buf| {
                                    send_buf.append(&mut buf);
                                    send_buf
                                })
                                .and_then(move |send_buf| -> io::Result<_> {
                                    try!(cipher.update(&send_buf[..], &mut iv));
                                    try!(cipher.finalize(&mut iv));
                                    Ok(iv)
                                })
                                .and_then(move |final_buf| {
                                    let svr_addr = svr_cfg.addr().listen_addr();
                                    let l = try!(UdpSocket::bind(svr_addr, &handle));
                                    Ok((l, final_buf))
                                })
                                .and_then(move |(l, final_buf)| send_to(l, final_buf, client_addr))
                                .map(|_| ());

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

    /// Starts a UDP relay server
    pub fn run(config: Rc<Config>, handle: Handle, dns_resolver: DnsResolver) -> BoxIoFuture<()> {
        let mut fut = boxed_future(futures::finished(()));

        for svr in &config.server {
            let handle = handle.clone();
            let dns_resolver = dns_resolver.clone();
            let svr_cfg = Rc::new(svr.clone());

            let svr_fut = fut.join(UdpRelayServer::run_server(svr_cfg, handle, dns_resolver));
            fut = boxed_future(svr_fut.map(|_| ()));
        }

        fut
    }
}