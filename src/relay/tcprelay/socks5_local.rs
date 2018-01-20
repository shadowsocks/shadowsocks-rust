//! Local server that accepts SOCKS 5 protocol

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;

use futures::{self, Future};
use futures::stream::Stream;

use tokio_core::net::{TcpListener, TcpStream};
use tokio_io::AsyncRead;
use tokio_io::io::{ReadHalf, WriteHalf};
use tokio_io::io::flush;

use config::ServerConfig;

use relay::{boxed_future, BoxIoFuture};
use relay::Context;
use relay::loadbalancing::server::LoadBalancer;
use relay::loadbalancing::server::RoundRobin;
use relay::socks5::{self, Address, HandshakeRequest, HandshakeResponse};
use relay::socks5::{TcpRequestHeader, TcpResponseHeader};
use relay::tcprelay::crypto_io::{DecryptedRead, EncryptedWrite};

use super::{ignore_until_end, try_timeout, tunnel};

#[derive(Debug, Clone)]
struct UdpConfig {
    enable_udp: bool,
    client_addr: Rc<SocketAddr>,
}

fn handle_socks5_connect((r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
                         client_addr: SocketAddr,
                         addr: Address,
                         svr_cfg: Rc<ServerConfig>)
                         -> BoxIoFuture<()> {
    let cloned_addr = addr.clone();
    let cloned_svr_cfg = svr_cfg.clone();
    let timeout = *svr_cfg.timeout();
    let fut = super::connect_proxy_server(svr_cfg)
        .then(move |res| {
            match res {
                Ok(svr_s) => {
                    trace!("Proxy server connected");

                    // Tell the client that we are ready
                    let header = TcpResponseHeader::new(socks5::Reply::Succeeded, Address::SocketAddress(client_addr));
                    trace!("Send header: {:?}", header);

                    let fut = Context::with(|ctx| {
                                                let handle = ctx.handle();
                                                let fut = try_timeout(header.write_to(w), timeout, &handle);
                                                try_timeout(fut.and_then(flush), timeout, &handle)
                                            });

                    boxed_future(fut.map(move |w| (svr_s, w)))
                }
                Err(err) => {
                    use std::io::ErrorKind;
                    use relay::socks5::Reply;

                    error!("Failed to connect remote server, {:?}", err);

                    let reply = match err.kind() {
                        ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                        ErrorKind::ConnectionAborted => Reply::HostUnreachable,
                        _ => Reply::NetworkUnreachable,
                    };

                    let header = TcpResponseHeader::new(reply, Address::SocketAddress(client_addr));
                    trace!("Send header: {:?}", header);

                    let fut = Context::with(|ctx| {
                                                let handle = ctx.handle();
                                                let fut = try_timeout(header.write_to(w), timeout, &handle);
                                                try_timeout(fut.and_then(flush), timeout, &handle)
                                            });

                    boxed_future(fut.and_then(|_| Err(err)))
                }
            }
        })
        .and_then(move |(svr_s, w)| {
            let svr_cfg = cloned_svr_cfg;
            let timeout = *svr_cfg.timeout();
            super::proxy_server_handshake(svr_s, svr_cfg, addr).and_then(move |(svr_r, svr_w)| {
                let cloned_timeout = timeout;
                let rhalf = svr_r.and_then(move |svr_r| svr_r.copy_timeout_opt(w, timeout));
                let whalf = svr_w.and_then(move |svr_w| svr_w.copy_timeout_opt(r, cloned_timeout));

                tunnel(cloned_addr, whalf, rhalf)
            })
        });

    Box::new(fut)
}

fn handle_socks5_client(s: TcpStream, conf: Rc<ServerConfig>, udp_conf: UdpConfig) -> io::Result<()> {
    let client_addr = s.peer_addr()?;
    let cloned_client_addr = client_addr;
    let fut = futures::lazy(|| Ok(s.split()))
        .and_then(|(r, w)| {
            // Socks5 handshakes
            HandshakeRequest::read_from(r).and_then(move |(r, req)| {
                trace!("Socks5 {:?}", req);

                if !req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
                    let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
                    let fut = resp.write_to(w).then(|_| {
                        warn!("Currently shadowsocks-rust does not support authentication");
                        Err(io::Error::new(io::ErrorKind::Other,
                                           "Currently shadowsocks-rust does not support authentication"))
                    });
                    boxed_future(fut)
                } else {
                    // Reply to client
                    let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                    trace!("Reply handshake {:?}", resp);
                    let fut = resp.write_to(w).and_then(flush).and_then(|w| Ok((r, w)));
                    boxed_future(fut)
                }
            })
        })
        .and_then(move |(r, w)| {
            // Fetch headers
            TcpRequestHeader::read_from(r).then(move |res| match res {
                                                    Ok((r, h)) => boxed_future(futures::finished((r, w, h))),
                                                    Err(err) => {
                                                        error!("Failed to get TcpRequestHeader: {}", err);
                                                        let fut =
                                                            TcpResponseHeader::new(err.reply,
                                                                                   Address::SocketAddress(client_addr))
                                                            .write_to(w)
                                                            .then(|_| Err(From::from(err)));
                                                        boxed_future(fut)
                                                    }
                                                })
        })
        .and_then(move |(r, w, header)| {
            trace!("Socks5 {:?}", header);

            let addr = header.address;
            match header.command {
                socks5::Command::TcpConnect => {
                    debug!("CONNECT {}", addr);
                    handle_socks5_connect((r, w), cloned_client_addr, addr, conf)
                }
                socks5::Command::TcpBind => {
                    warn!("BIND is not supported");
                    let fut = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                        .write_to(w)
                        .map(|_| ());
                    boxed_future(fut)
                }
                socks5::Command::UdpAssociate => {
                    if udp_conf.enable_udp {
                        debug!("UDP ASSOCIATE {}", addr);
                        let fut = TcpResponseHeader::new(socks5::Reply::Succeeded, From::from(*udp_conf.client_addr))
                            .write_to(w)
                            .and_then(flush)
                            .and_then(|_| {
                                          // Hold the connection until it ends by its own
                                          ignore_until_end(r).map(|_| ())
                                      });

                        boxed_future(fut)
                    } else {
                        warn!("UDP Associate is not enabled");
                        let fut = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                            .write_to(w)
                            .map(|_| ());
                        boxed_future(fut)
                    }
                }
            }
        });

    // Runs in Tokio
    Context::with(|ctx| {
                      let handle = &ctx.handle;
                      handle.spawn(fut.then(|res| match res {
                                                Ok(..) => Ok(()),
                                                Err(err) => {
                                                    if err.kind() != io::ErrorKind::BrokenPipe {
                                                        error!("Failed to handle client: {}", err);
                                                    }
                                                    Err(())
                                                }
                                            }));
                  });

    Ok(())
}

/// Starts a TCP local server with Socks5 proxy protocol
pub fn run() -> Box<Future<Item = (), Error = io::Error>> {
    let (listener, local_addr) = Context::with(|ctx| {
                                                   let config = &ctx.config;
                                                   let handle = &ctx.handle;

                                                   let local_addr = config.local.as_ref().unwrap();

                                                   let l = TcpListener::bind(&local_addr, &handle)
                                                        .unwrap_or_else(|err| panic!("Failed to listen, {}", err));

                                                   info!("ShadowSocks TCP Listening on {}", local_addr);
                                                   (l, *local_addr)
                                               });

    let udp_conf = UdpConfig { enable_udp: Context::with(|ctx| ctx.config.enable_udp),
                               client_addr: Rc::new(local_addr), };

    let mut servers = Context::with(|ctx| RoundRobin::new(ctx.config()));
    let listening = listener.incoming().for_each(move |(socket, addr)| {
                                                     let server_cfg = servers.pick_server();
                                                     trace!("Got connection, addr: {}", addr);
                                                     trace!("Picked proxy server: {:?}", server_cfg);
                                                     handle_socks5_client(socket, server_cfg, udp_conf.clone())
                                                 });

    Box::new(listening.map_err(|err| {
                                   error!("Socks5 server run failed: {}", err);
                                   err
                               }))
}
