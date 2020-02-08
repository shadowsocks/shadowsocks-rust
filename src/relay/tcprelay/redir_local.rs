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
        socks5::Address,
    },
};

use super::sys::{create_redir_listener, get_original_destination_addr};

/// Established Client Transparent Proxy
///
/// This method must be called after handshaking with client (for example, socks5 handshaking)
async fn establish_client_tcp_redir<'a>(
    server: &SharedPlainServerStatistic,
    mut s: TcpStream,
    client_addr: SocketAddr,
    addr: &Address,
) -> io::Result<()> {
    let context = server.context();
    let svr_cfg = server.server_config();

    let svr_s = match super::connect_proxy_server(context, svr_cfg).await {
        Ok(svr_s) => {
            trace!("Proxy server connected, {:?}", svr_cfg);
            svr_s
        }
        Err(err) => {
            // Report to global statistic
            server.report_failure().await;

            // Just close the connection.
            error!("Failed to connect remote server {}, err: {}", svr_cfg.addr(), err);
            return Err(err);
        }
    };

    let mut svr_s = super::proxy_server_handshake(server.clone_context(), svr_s, svr_cfg, addr).await?;
    let (mut svr_r, mut svr_w) = svr_s.split();

    let (mut r, mut w) = s.split();

    use tokio::io::copy;

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    debug!(
        "REDIR relay established {} <-> {} ({})",
        client_addr,
        svr_cfg.addr(),
        addr
    );

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!("REDIR relay {} -> {} ({}) closed", client_addr, svr_cfg.addr(), addr),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!(
                    "REDIR relay {} -> {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            } else {
                error!(
                    "REDIR relay {} -> {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            }
        }
        Either::Right((Ok(..), _)) => trace!("REDIR relay {} <- {} ({}) closed", client_addr, svr_cfg.addr(), addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!(
                    "REDIR relay {} <- {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            } else {
                error!(
                    "REDIR relay {} <- {} ({}) closed with error {}",
                    client_addr,
                    svr_cfg.addr(),
                    addr,
                    err,
                );
            }
        }
    }

    debug!("REDIR relay {} <-> {} ({}) closed", client_addr, svr_cfg.addr(), addr);

    Ok(())
}

async fn handle_redir_client(server: &SharedPlainServerStatistic, mut s: TcpStream) -> io::Result<()> {
    let svr_cfg = server.server_config();

    if let Err(err) = s.set_keepalive(svr_cfg.timeout()) {
        error!("Failed to set keep alive: {:?}", err);
    }

    if server.config().no_delay {
        if let Err(err) = s.set_nodelay(true) {
            error!("Failed to set TCP_NODELAY on accepted socket, error: {:?}", err);
        }
    }

    let client_addr = s.peer_addr()?;

    // Get forward address from socket
    let target_addr = Address::from(get_original_destination_addr(&mut s)?);

    trace!("REDIR target address {}", target_addr);

    establish_client_tcp_redir(server, s, client_addr, &target_addr).await
}

pub async fn run(context: SharedContext) -> io::Result<()> {
    if let Err(err) = super::sys::check_support_tproxy() {
        panic!("{}", err);
    }

    let local_addr = context.config().local.as_ref().expect("Missing local config");
    let bind_addr = local_addr.bind_addr(&*context).await?;

    let mut listener = create_redir_listener(&bind_addr)
        .await
        .unwrap_or_else(|err| panic!("Failed to listen on {}, {}", local_addr, err));

    let actual_local_addr = listener.local_addr().expect("Could not determine port bound to");

    let servers = PlainPingBalancer::new(context.clone(), ServerType::Tcp).await;
    info!("ShadowSocks TCP Redir Listening on {}", actual_local_addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let server = servers.pick_server();

        trace!("Got connection, addr: {}", peer_addr);
        trace!("Picked proxy server: {:?}", server.server_config());

        tokio::spawn(async move {
            if let Err(err) = handle_redir_client(&server, socket).await {
                error!("TCP Redir client, error: {:?}", err);
            }
        });
    }
}
