//! Local server that accepts SOCKS 5 protocol

use std::{
    io,
    io::ErrorKind,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use futures::future::{self, Either};
use log::{debug, error, info, trace, warn};
use tokio::{
    self,
    net::{TcpListener, TcpStream},
};

use crate::{
    config::ServerConfig,
    context::{Context, SharedContext},
    relay::{
        loadbalancing::server::{LoadBalancer, PingBalancer, PingServer, PingServerType},
        socks5::{self, Address, HandshakeRequest, HandshakeResponse, TcpRequestHeader, TcpResponseHeader},
    },
};

use super::ignore_until_end;

#[derive(Debug, Clone)]
struct UdpConfig {
    enable_udp: bool,
    client_addr: SocketAddr,
}

async fn handle_socks5_connect<'a>(
    context: &Context,
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    addr: &Address,
    svr_cfg: &ServerConfig,
) -> io::Result<()> {
    let svr_s = match super::connect_proxy_server(context, svr_cfg).await {
        Ok(svr_s) => {
            trace!("Proxy server connected, {:?}", svr_cfg);

            // Tell the client that we are ready
            let header = TcpResponseHeader::new(socks5::Reply::Succeeded, Address::SocketAddress(svr_s.local_addr()?));
            header.write_to(stream).await?;

            trace!("Sent header: {:?}", header);

            svr_s
        }
        Err(err) => {
            use crate::relay::socks5::Reply;

            error!("Failed to connect remote server {}, err: {}", svr_cfg.addr(), err);

            let reply = match err.kind() {
                ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                ErrorKind::ConnectionAborted => Reply::HostUnreachable,
                _ => Reply::NetworkUnreachable,
            };

            let header = TcpResponseHeader::new(
                reply,
                Address::SocketAddress("0.0.0.0:0".parse::<SocketAddr>().unwrap()),
            );
            header.write_to(stream).await?;

            return Err(err);
        }
    };

    let mut svr_s = super::proxy_server_handshake(context, svr_s, svr_cfg, addr).await?;
    let (mut svr_r, mut svr_w) = svr_s.split();

    // Reset `TCP_NODELAY` after Socks5 handshake
    if !context.config().no_delay {
        if let Err(err) = stream.set_nodelay(false) {
            error!("Failed to reset TCP_NODELAY on socket, error: {:?}", err);
        }
    }

    let (mut r, mut w) = stream.split();

    use tokio::io::copy;

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    debug!(
        "CONNECT relay established {} <-> {} ({})",
        client_addr,
        svr_cfg.addr(),
        addr
    );

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!("CONNECT relay {} -> {} ({}) closed", client_addr, svr_cfg.addr(), addr),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!(
                    "CONNECT relay {} -> {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            } else {
                error!(
                    "CONNECT relay {} -> {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            }
        }
        Either::Right((Ok(..), _)) => trace!("CONNECT relay {} <- {} ({}) closed", client_addr, svr_cfg.addr(), addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!(
                    "CONNECT relay {} <- {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            } else {
                error!(
                    "CONNECT relay {} <- {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            }
        }
    }

    debug!("CONNECT relay {} <-> {} ({}) closed", client_addr, svr_cfg.addr(), addr);

    Ok(())
}

#[allow(clippy::cognitive_complexity)]
async fn handle_socks5_client(
    context: &Context,
    mut s: TcpStream,
    server_conf: Arc<ServerScore>,
    udp_conf: UdpConfig,
) -> io::Result<()> {
    let conf = server_conf.server_config();

    if let Err(err) = s.set_keepalive(conf.timeout()) {
        error!("Failed to set keep alive: {:?}", err);
    }

    // Enable TCP_NODELAY for quick handshaking
    if let Err(err) = s.set_nodelay(true) {
        error!("Failed to set TCP_NODELAY on accepted socket, error: {:?}", err);
    }

    let client_addr = s.peer_addr()?;

    let handshake_req = HandshakeRequest::read_from(&mut s).await?;

    // Socks5 handshakes
    trace!("Socks5 {:?}", handshake_req);

    let (handshake_resp, res) = if !handshake_req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
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

    handshake_resp.write_to(&mut s).await?;

    res?;

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
            let enable_tcp = context.config().mode.enable_tcp();
            if enable_tcp {
                debug!("CONNECT {}", addr);

                match handle_socks5_connect(context, &mut s, client_addr, &addr, conf).await {
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
            if udp_conf.enable_udp {
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

struct ServerScore {
    svr_cfg: ServerConfig,
    score: AtomicU64,
}

impl ServerScore {
    fn new(config: &ServerConfig) -> Arc<ServerScore> {
        let s = ServerScore {
            svr_cfg: config.clone(),
            score: AtomicU64::new(0),
        };
        Arc::new(s)
    }
}

impl PingServer for ServerScore {
    fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    fn score(&self) -> u64 {
        self.score.load(Ordering::Acquire)
    }

    fn set_score(&self, score: u64) {
        self.score.store(score, Ordering::Release);
    }
}

/// Starts a TCP local server with Socks5 proxy protocol
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local.as_ref().expect("Missing local config");
    let bind_addr = local_addr.bind_addr(&*context).await?;

    let mut listener = TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|err| panic!("Failed to listen on {}, {}", local_addr, err));

    let actual_local_addr = listener.local_addr().expect("Could not determine port bound to");

    let udp_conf = UdpConfig {
        enable_udp: context.config().mode.enable_udp(),
        client_addr: actual_local_addr,
    };

    let servers = context.config().server.iter().map(ServerScore::new).collect();
    let mut servers = PingBalancer::new(context.clone(), servers, PingServerType::Tcp).await;

    info!("ShadowSocks TCP Listening on {}", actual_local_addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let server_cfg = servers.pick_server();

        trace!("Got connection, addr: {}", peer_addr);
        trace!("Picked proxy server: {:?}", server_cfg.server_config());

        let context = context.clone();
        let udp_conf = udp_conf.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_socks5_client(&*context, socket, server_cfg, udp_conf).await {
                error!("TCP Socks5 client, error: {:?}", err);
            }
        });
    }
}
