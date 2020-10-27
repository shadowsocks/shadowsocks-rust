//! Local server that accepts SOCKS4 protocol

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use futures::future::{self, Either};
use log::{debug, error, info, trace, warn};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType, SharedPlainServerStatistic},
        socks4::{Address, Command, HandshakeRequest, HandshakeResponse, ResultCode},
        tcprelay::ProxyStream,
    },
};

async fn handle_socks4_connect(
    server: &SharedPlainServerStatistic,
    mut stream: BufReader<TcpStream>,
    client_addr: SocketAddr,
    addr: Address,
) -> io::Result<()> {
    let context = server.context();
    let svr_cfg = server.server_config();

    // NOTE: Shadowsocks server uses SOCKS5 Address
    let ss_addr = addr.into();

    let mut svr_s = match ProxyStream::connect(server.clone_context(), svr_cfg, &ss_addr).await {
        Ok(svr_s) => {
            // Tell the client that we are ready
            let handshake_rsp = HandshakeResponse::new(ResultCode::RequestGranted);
            handshake_rsp.write_to(&mut stream).await?;

            trace!("sent header: {:?}", handshake_rsp);

            svr_s
        }
        Err(perr) => {
            if perr.is_proxied() {
                // Report to global statistic
                server.report_failure().await;
            }

            let err = perr.into_inner();
            let result_code = match err.kind() {
                ErrorKind::ConnectionRefused => ResultCode::RequestRejectedCannotConnect,
                ErrorKind::ConnectionAborted => ResultCode::RequestRejectedCannotConnect,
                _ => ResultCode::RequestRejectedOrFailed,
            };

            let handshake_rsp = HandshakeResponse::new(result_code);
            handshake_rsp.write_to(&mut stream).await?;

            return Err(err);
        }
    };

    // NOTE: Transfer all buffered data before unwrap, or these data will be lost
    let buffer = stream.buffer();
    if !buffer.is_empty() {
        svr_s.write_all(buffer).await?;
    }

    // UNWRAP.
    let mut stream = stream.into_inner();

    // Reset `TCP_NODELAY` after Socks5 handshake
    if !context.config().no_delay {
        if let Err(err) = stream.set_nodelay(false) {
            error!("failed to reset TCP_NODELAY on socket, error: {:?}", err);
        }
    }

    let (mut svr_r, mut svr_w) = svr_s.split();
    let (mut r, mut w) = stream.split();

    use tokio::io::copy;

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    debug!("CONNECT relay established {} <-> {}", client_addr, ss_addr);

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!("CONNECT relay {} -> {} closed", client_addr, ss_addr),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("CONNECT relay {} -> {} closed with error {}", client_addr, ss_addr, err);
            } else {
                error!("CONNECT relay {} -> {} closed with error {}", client_addr, ss_addr, err);
            }
        }
        Either::Right((Ok(..), _)) => trace!("CONNECT relay {} <- {} closed", client_addr, ss_addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("CONNECT relay {} <- {} closed with error {}", client_addr, ss_addr, err);
            } else {
                error!("CONNECT relay {} <- {} closed with error {}", client_addr, ss_addr, err);
            }
        }
    }

    debug!("CONNECT relay {} <-> {} closed", client_addr, ss_addr);

    Ok(())
}

async fn handle_socks4_client(server: &SharedPlainServerStatistic, s: TcpStream) -> io::Result<()> {
    let svr_cfg = server.server_config();

    if let Err(err) = s.set_keepalive(svr_cfg.timeout()) {
        error!("failed to set keep alive: {:?}", err);
    }

    // Enable TCP_NODELAY for quick handshaking
    if let Err(err) = s.set_nodelay(true) {
        error!("failed to set TCP_NODELAY on accepted socket, error: {:?}", err);
    }

    let client_addr = s.peer_addr()?;

    // NOTE: Wraps it with BufReader for reading NULL terminated informations in HandshakeRequest
    let mut s = BufReader::new(s);
    let handshake_req = HandshakeRequest::read_from(&mut s).await?;

    trace!("socks4 {:?}", handshake_req);

    match handshake_req.cd {
        Command::Connect => {
            debug!("CONNECT {}", handshake_req.dst);

            handle_socks4_connect(server, s, client_addr, handshake_req.dst).await
        }
        Command::Bind => {
            warn!("BIND is not supported");

            let handshake_rsp = HandshakeResponse::new(ResultCode::RequestRejectedOrFailed);
            handshake_rsp.write_to(&mut s).await?;

            Ok(())
        }
    }
}

/// Starts a TCP local server with Socks4 proxy protocol
pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local_addr.as_ref().expect("local config");
    let bind_addr = local_addr.bind_addr(&context).await?;

    let mut listener = TcpListener::bind(&bind_addr).await.map_err(|err| {
        error!("failed to listen on {} ({}), {}", local_addr, bind_addr, err);
        err
    })?;

    let actual_local_addr = listener.local_addr().expect("determine port bound to");

    let servers = PlainPingBalancer::new(context, ServerType::Tcp).await;

    info!("shadowsocks SOCKS4/4a TCP listening on {}", actual_local_addr);

    loop {
        let (socket, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                error!("accept failed with error: {}", err);
                time::delay_for(Duration::from_secs(1)).await;
                continue;
            }
        };
        let server = servers.pick_server();

        trace!("got connection {}", peer_addr);
        trace!("picked proxy server: {:?}", server.server_config());

        tokio::spawn(async move {
            if let Err(err) = handle_socks4_client(&server, socket).await {
                error!("TCP socks4 client exited with error: {}", err);
            }
        });
    }
}
