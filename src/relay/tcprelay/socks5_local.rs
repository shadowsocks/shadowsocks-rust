//! Local server that accepts SOCKS5 protocol

use std::{
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use futures::future::{self, Either};
use log::{debug, error, info, trace, warn};
use tokio::{
    self,
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType, SharedPlainServerStatistic},
        socks5::{self, Address, HandshakeRequest, HandshakeResponse, TcpRequestHeader, TcpResponseHeader},
    },
};

use super::{ignore_until_end, ProxyStream};

#[derive(Debug, Clone)]
struct UdpConfig {
    enable_udp: bool,
    client_addr: SocketAddr,
}

async fn handle_socks5_connect(
    server: &SharedPlainServerStatistic,
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    addr: &Address,
) -> io::Result<()> {
    let context = server.context();
    let svr_cfg = server.server_config();

    let svr_s = match ProxyStream::connect(server.clone_context(), svr_cfg, addr).await {
        Ok(svr_s) => {
            // Tell the client that we are ready
            let header = TcpResponseHeader::new(socks5::Reply::Succeeded, Address::SocketAddress(svr_s.local_addr()?));
            header.write_to(stream).await?;

            trace!("sent header: {:?}", header);

            svr_s
        }
        Err(perr) => {
            use crate::relay::socks5::Reply;

            if perr.is_proxied() {
                // Report to global statistic
                server.report_failure().await;
            }

            let err = perr.into_inner();
            let reply = match err.kind() {
                ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                ErrorKind::ConnectionAborted => Reply::HostUnreachable,
                _ => Reply::NetworkUnreachable,
            };

            let dummy_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
            let header = TcpResponseHeader::new(reply, Address::SocketAddress(dummy_address));
            header.write_to(stream).await?;

            return Err(err);
        }
    };

    let (mut svr_r, mut svr_w) = svr_s.split();

    // Reset `TCP_NODELAY` after Socks5 handshake
    if !context.config().no_delay {
        if let Err(err) = stream.set_nodelay(false) {
            error!("failed to reset TCP_NODELAY on socket, error: {:?}", err);
        }
    }

    let (mut r, mut w) = stream.split();

    use tokio::io::copy;

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    tokio::pin!(rhalf);
    tokio::pin!(whalf);

    debug!("CONNECT relay established {} <-> {}", client_addr, addr);

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!("CONNECT relay {} -> {} closed", client_addr, addr),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("CONNECT relay {} -> {} closed with error {}", client_addr, addr, err);
            } else {
                error!("CONNECT relay {} -> {} closed with error {}", client_addr, addr, err);
            }
        }
        Either::Right((Ok(..), _)) => trace!("CONNECT relay {} <- {} closed", client_addr, addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("CONNECT relay {} <- {} closed with error {}", client_addr, addr, err);
            } else {
                error!("CONNECT relay {} <- {} closed with error {}", client_addr, addr, err);
            }
        }
    }

    debug!("CONNECT relay {} <-> {} closed", client_addr, addr);

    Ok(())
}

#[allow(clippy::cognitive_complexity)]
async fn handle_socks5_client(
    server: &SharedPlainServerStatistic,
    mut s: TcpStream,
    udp_conf: UdpConfig,
) -> io::Result<()> {
    // let svr_cfg = server.server_config();
    //
    // FIXME: set_keepalive have been removed from tokio 0.3
    //        Related issue: https://github.com/rust-lang/rust/issues/69774
    // if let Err(err) = s.set_keepalive(svr_cfg.timeout()) {
    //     error!("failed to set keep alive: {:?}", err);
    // }

    // Enable TCP_NODELAY for quick handshaking
    if let Err(err) = s.set_nodelay(true) {
        error!("failed to set TCP_NODELAY on accepted socket, error: {:?}", err);
    }

    let client_addr = s.peer_addr()?;

    let handshake_req = HandshakeRequest::read_from(&mut s).await?;

    // Socks5 handshakes
    trace!("socks5 {:?}", handshake_req);

    if !handshake_req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
        use std::io::Error;

        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
        resp.write_to(&mut s).await?;

        return Err(Error::new(
            ErrorKind::Other,
            "currently shadowsocks-rust does not support authentication",
        ));
    } else {
        // Reply to client
        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
        trace!("Reply handshake {:?}", resp);
        resp.write_to(&mut s).await?;
    }

    // Fetch headers
    let header = match TcpRequestHeader::read_from(&mut s).await {
        Ok(h) => h,
        Err(err) => {
            error!("Failed to get TcpRequestHeader: {}", err);
            let rh = TcpResponseHeader::new(err.reply, Address::SocketAddress(client_addr));
            rh.write_to(&mut s).await?;
            return Err(From::from(err));
        }
    };

    trace!("Socks5 {:?}", header);

    let addr = header.address;
    match header.command {
        socks5::Command::TcpConnect => {
            let enable_tcp = server.config().mode.enable_tcp();
            if enable_tcp {
                debug!("CONNECT {}", addr);

                match handle_socks5_connect(server, &mut s, client_addr, &addr).await {
                    Ok(..) => Ok(()),
                    Err(err) => Err(io::Error::new(
                        err.kind(),
                        format!("CONNECT {} failed with error \"{}\"", addr, err),
                    )),
                }
            } else {
                warn!("CONNECT is not enabled");
                let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr);
                rh.write_to(&mut s).await?;

                Ok(())
            }
        }
        socks5::Command::TcpBind => {
            warn!("BIND is not supported");
            let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr);
            rh.write_to(&mut s).await?;

            Ok(())
        }
        socks5::Command::UdpAssociate => {
            if let Some(ref bind_addr) = server.config().udp_bind_addr {
                debug!("UDP ASSOCIATE {}", addr);

                let rh = TcpResponseHeader::new(socks5::Reply::Succeeded, bind_addr.into());
                rh.write_to(&mut s).await?;

                // Hold the connection until it ends by its own
                ignore_until_end(&mut s).await?;

                Ok(())
            } else if udp_conf.enable_udp {
                debug!("UDP ASSOCIATE {}", addr);
                let rh = TcpResponseHeader::new(socks5::Reply::Succeeded, From::from(udp_conf.client_addr));
                rh.write_to(&mut s).await?;

                // Hold the connection until it ends by its own
                ignore_until_end(&mut s).await?;

                Ok(())
            } else {
                warn!("UDP ASSOCIATE is not enabled");
                let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr);
                rh.write_to(&mut s).await?;

                Ok(())
            }
        }
    }
}

/// Starts a TCP local server with Socks5 proxy protocol
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local_addr.as_ref().expect("local config");
    let bind_addr = local_addr.bind_addr(&context).await?;

    let listener = TcpListener::bind(&bind_addr).await.map_err(|err| {
        error!("failed to listen on {} ({}), {}", local_addr, bind_addr, err);
        err
    })?;

    let actual_local_addr = listener.local_addr().expect("determine port bound to");

    let udp_conf = UdpConfig {
        enable_udp: context.config().mode.enable_udp(),
        client_addr: actual_local_addr,
    };

    let servers = PlainPingBalancer::new(context, ServerType::Tcp).await;

    info!("shadowsocks SOCKS5 TCP listening on {}", actual_local_addr);

    loop {
        let (socket, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                error!("accept failed with error: {}", err);
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let server = servers.pick_server();

        trace!("got connection {}", peer_addr);
        trace!("picked proxy server: {:?}", server.server_config());

        let udp_conf = udp_conf.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_socks5_client(&server, socket, udp_conf).await {
                error!("TCP socks5 client exited with error: {}", err);
            }
        });
    }
}
