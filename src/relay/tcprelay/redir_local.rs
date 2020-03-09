//! Local server that establish a TCP Transparent Proxy with server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use futures::future::{self, Either};
use log::{debug, error, info, trace};
use tokio::net::TcpStream;

use crate::{
    context::SharedContext,
    relay::{
        loadbalancing::server::{PlainPingBalancer, ServerType, SharedPlainServerStatistic},
        redir::TcpListenerRedirExt,
        socks5::Address,
    },
};

use super::{sys::TcpRedirListener, ProxyStream};

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
                error!("REDIR relay {} -> {} closed with error {}", client_addr, addr, err);
            }
        }
        Either::Right((Ok(..), _)) => trace!("REDIR relay {} <- {} closed", client_addr, addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("REDIR relay {} <- {} closed with error {}", client_addr, addr, err);
            } else {
                error!("REDIR relay {} <- {} closed with error {}", client_addr, addr, err);
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
    let local_addr = context.config().local.as_ref().expect("local config");
    let bind_addr = local_addr.bind_addr(&*context).await?;

    let mut listener = TcpRedirListener::bind(context.config().tcp_redir, &bind_addr)
        .await
        .unwrap_or_else(|err| panic!("Failed to listen on {}, {}", local_addr, err));

    let actual_local_addr = listener.local_addr().expect("determine port bound to");

    let servers = PlainPingBalancer::new(context.clone(), ServerType::Tcp).await;
    info!("shadowsocks TCP redirect listening on {}", actual_local_addr);

    loop {
        let (socket, peer_addr, dst_addr) = listener.accept_redir().await?;

        let dst_addr = match dst_addr {
            Some(d) => d,
            None => {
                error!("got connection {} without destination address", peer_addr);
                continue;
            }
        };

        let server = servers.pick_server();

        trace!("got connection {}, destination: {}", peer_addr, dst_addr);
        trace!("picked proxy server: {:?}", server.server_config());

        tokio::spawn(async move {
            if let Err(err) = handle_redir_client(&server, socket, dst_addr).await {
                error!("TCP redirect client, error: {:?}", err);
            }
        });
    }
}
