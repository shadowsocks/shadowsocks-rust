//! Local server that accepts SOCKS 5 protocol

use std::{io, net::SocketAddr, sync::Arc};

use futures::{self, stream::Stream, Future};

use log::{debug, error, info, trace, warn};
use tokio::{
    self,
    net::{TcpListener, TcpStream},
};
use tokio_io::{
    io::{flush, ReadHalf, WriteHalf},
    AsyncRead,
};

use crate::{config::ServerConfig, context::SharedContext};

use crate::relay::{
    boxed_future,
    loadbalancing::server::{LoadBalancer, RoundRobin},
    socks5::{self, Address, HandshakeRequest, HandshakeResponse, TcpRequestHeader, TcpResponseHeader},
    tcprelay::crypto_io::{DecryptedRead, EncryptedWrite},
};

use super::{ignore_until_end, try_timeout, tunnel};

#[derive(Debug, Clone)]
struct UdpConfig {
    enable_udp: bool,
    client_addr: SocketAddr,
}

fn handle_socks5_connect(
    context: SharedContext,
    (r, w): (ReadHalf<TcpStream>, WriteHalf<TcpStream>),
    client_addr: SocketAddr,
    addr: Address,
    svr_cfg: Arc<ServerConfig>,
) -> impl Future<Item = (), Error = io::Error> + Send {
    let timeout = svr_cfg.timeout();
    super::connect_proxy_server(context, svr_cfg.clone())
        .then(move |res| {
            let (header, r) = match res {
                Ok(svr_s) => {
                    trace!("Proxy server connected");

                    // Tell the client that we are ready
                    let header = TcpResponseHeader::new(socks5::Reply::Succeeded, Address::SocketAddress(client_addr));

                    (header, Ok(svr_s))
                }
                Err(err) => {
                    use crate::relay::socks5::Reply;
                    use std::io::ErrorKind;

                    error!("Failed to connect remote server, err: {}", err);

                    let reply = match err.kind() {
                        ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                        ErrorKind::ConnectionAborted => Reply::HostUnreachable,
                        _ => Reply::NetworkUnreachable,
                    };

                    let header = TcpResponseHeader::new(reply, Address::SocketAddress(client_addr));

                    (header, Err(err))
                }
            };

            trace!("Sent header: {:?}", header);
            try_timeout(header.write_to(w).and_then(flush), timeout).and_then(|w| match r {
                Ok(svr_s) => Ok((svr_s, w)),
                Err(err) => Err(err),
            })
        })
        .and_then(move |(svr_s, w)| {
            let timeout = svr_cfg.timeout();
            super::proxy_server_handshake(svr_s, svr_cfg, addr).and_then(move |(svr_r, svr_w)| {
                let rhalf = svr_r.and_then(move |svr_r| svr_r.copy_timeout_opt(w, timeout));
                let whalf = svr_w.and_then(move |svr_w| svr_w.copy_timeout_opt(r, timeout));
                tunnel(whalf, rhalf)
            })
        })
}

fn handle_socks5_client(
    context: SharedContext,
    s: TcpStream,
    conf: Arc<ServerConfig>,
    udp_conf: UdpConfig,
) -> io::Result<()> {
    if let Err(err) = s.set_keepalive(conf.timeout()) {
        error!("Failed to set keep alive: {:?}", err);
    }

    if context.config().no_delay {
        if let Err(err) = s.set_nodelay(true) {
            error!("Failed to set no delay: {:?}", err);
        }
    }

    let client_addr = s.peer_addr()?;
    let cloned_client_addr = client_addr;
    let fut = futures::lazy(|| Ok(s.split()))
        .and_then(|(r, w)| {
            // Socks5 handshakes
            HandshakeRequest::read_from(r).and_then(move |(r, req)| {
                trace!("Socks5 {:?}", req);

                let (resp, res) = if !req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
                    let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
                    warn!("Currently shadowsocks-rust does not support authentication");
                    (
                        resp,
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Currently shadowsocks-rust does not support authentication",
                        )),
                    )
                } else {
                    // Reply to client
                    let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                    trace!("Reply handshake {:?}", resp);
                    (resp, Ok(()))
                };

                resp.write_to(w).and_then(flush).and_then(move |w| match res {
                    Ok(..) => Ok((r, w)),
                    Err(err) => Err(err),
                })
            })
        })
        .and_then(move |(r, w)| {
            // Fetch headers
            TcpRequestHeader::read_from(r).then(move |res| match res {
                Ok((r, h)) => boxed_future(futures::finished((r, w, h))),
                Err(err) => {
                    error!("Failed to get TcpRequestHeader: {}", err);
                    let fut = TcpResponseHeader::new(err.reply, Address::SocketAddress(client_addr))
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
                    let enable_tcp = context.config().mode.enable_tcp();
                    if enable_tcp {
                        debug!("CONNECT {}", addr);
                        let fut = handle_socks5_connect(context, (r, w), cloned_client_addr, addr.clone(), conf)
                            .map_err(move |err| {
                                io::Error::new(err.kind(), format!("CONNECT {} failed with error \"{}\"", addr, err))
                            });
                        boxed_future(fut)
                    } else {
                        warn!("CONNECT is not enabled");
                        let fut = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                            .write_to(w)
                            .map(|_| ());
                        boxed_future(fut)
                    }
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
                        let fut = TcpResponseHeader::new(socks5::Reply::Succeeded, From::from(udp_conf.client_addr))
                            .write_to(w)
                            .and_then(flush)
                            .and_then(|_| {
                                // Hold the connection until it ends by its own
                                ignore_until_end(r).map(|_| ())
                            });

                        boxed_future(fut)
                    } else {
                        warn!("UDP ASSOCIATE is not enabled");
                        let fut = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr)
                            .write_to(w)
                            .map(|_| ());
                        boxed_future(fut)
                    }
                }
            }
        });

    tokio::spawn(fut.then(|res| match res {
        Ok(..) => Ok(()),
        Err(err) => {
            if err.kind() != io::ErrorKind::BrokenPipe {
                error!("Socks5 client: {}", err);
            }
            Err(())
        }
    }));

    Ok(())
}

/// Starts a TCP local server with Socks5 proxy protocol
pub fn run(context: SharedContext) -> impl Future<Item = (), Error = io::Error> + Send {
    let local_addr = *context.config().local.as_ref().expect("Missing local config");

    let listener =
        TcpListener::bind(&local_addr).unwrap_or_else(|err| panic!("Failed to listen on {}, {}", local_addr, err));

    let actual_local_addr = listener.local_addr().expect("Could not determine port bound to");

    info!("ShadowSocks TCP Listening on {}", actual_local_addr);

    let udp_conf = UdpConfig {
        enable_udp: context.config().mode.enable_udp(),
        client_addr: actual_local_addr,
    };

    let mut servers = RoundRobin::new(context.config());
    listener.incoming().for_each(move |socket| {
        let server_cfg = servers.pick_server();

        trace!("Got connection, addr: {}", socket.peer_addr()?);
        trace!("Picked proxy server: {:?}", server_cfg);

        handle_socks5_client(context.clone(), socket, server_cfg, udp_conf.clone())
    })
}
