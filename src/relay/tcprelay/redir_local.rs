//! Local server that establish a TCP Transparent Proxy with server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use futures::future::{self, Either};
use log::{debug, error, info, trace};
use tokio::{
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType, SharedPlainServerStatistic},
        redir::{TcpListenerRedirExt, TcpStreamRedirExt},
        socks5::Address,
    },
};

use super::ProxyStream;

/// Established Client Transparent Proxy
///
/// This method must be called after handshaking with client (for example, socks5 handshaking)
async fn establish_client_tcp_redir<'a>(
    server: &SharedPlainServerStatistic,
    mut s: TcpStream,
    client_addr: SocketAddr,
    addr: &Address,
) -> io::Result<()> {
    let svr_cfg = server.server_config();

    let svr_s = ProxyStream::connect(server.clone_context(), svr_cfg, addr).await?;
    let (mut svr_r, mut svr_w) = svr_s.split();

    let (mut r, mut w) = s.split();

    use tokio::io::copy;

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    debug!("REDIR relay established {} <-> {}", client_addr, addr);

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!("REDIR relay {} -> {} closed", client_addr, addr),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("REDIR relay {} -> {} closed with error {}", client_addr, addr, err);
            } else {
                debug!("REDIR relay {} -> {} closed with error {}", client_addr, addr, err);
            }
        }
        Either::Right((Ok(..), _)) => trace!("REDIR relay {} <- {} closed", client_addr, addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("REDIR relay {} <- {} closed with error {}", client_addr, addr, err);
            } else {
                debug!("REDIR relay {} <- {} closed with error {}", client_addr, addr, err);
            }
        }
    }

    debug!("REDIR relay {} <-> {} closed", client_addr, addr);

    Ok(())
}

async fn handle_redir_client(server: &SharedPlainServerStatistic, s: TcpStream, daddr: SocketAddr) -> io::Result<()> {
    let svr_cfg = server.server_config();

    if let Err(err) = s.set_keepalive(svr_cfg.timeout()) {
        error!("failed to set keep alive: {:?}", err);
    }

    if server.config().no_delay {
        if let Err(err) = s.set_nodelay(true) {
            error!("failed to set TCP_NODELAY on accepted socket, error: {:?}", err);
        }
    }

    let client_addr = s.peer_addr()?;

    // Get forward address from socket
    let target_addr = Address::from(daddr);
    establish_client_tcp_redir(server, s, client_addr, &target_addr).await
}

pub async fn run(context: SharedContext) -> io::Result<()> {
    let local_addr = context.config().local_addr.as_ref().expect("local config");
    let bind_addr = local_addr.bind_addr(&context).await?;

    let redir_ty = context.config().tcp_redir;

    let mut listener = TcpListener::bind_redir(redir_ty, &bind_addr).await.map_err(|err| {
        error!("failed to listen on {} ({}), {}", local_addr, bind_addr, err);
        err
    })?;

    let actual_local_addr = listener.local_addr().expect("determine port bound to");

    let servers = PlainPingBalancer::new(context.clone(), ServerType::Tcp).await;
    info!("shadowsocks TCP redirect listening on {}", actual_local_addr);

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
            let dst_addr = match socket.destination_addr(redir_ty) {
                Ok(d) => d,
                Err(err) => {
                    error!(
                        "TCP redirect couldn't get destination, peer: {}, error: {}",
                        peer_addr, err
                    );
                    return;
                }
            };

            if let Err(err) = handle_redir_client(&server, socket, dst_addr).await {
                debug!("TCP redirect client, error: {:?}", err);
            }
        });
    }
}
