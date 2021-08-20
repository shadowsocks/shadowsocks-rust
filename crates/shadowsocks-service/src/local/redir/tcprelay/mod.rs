//! Shadowsocks TCP transparent proxy

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use log::{debug, error, info, trace};
use shadowsocks::{lookup_then, net::TcpListener as ShadowTcpListener, relay::socks5::Address, ServerAddr};
use tokio::{
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    config::RedirType,
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::AutoProxyClientStream,
        redir::redir_ext::{TcpListenerRedirExt, TcpStreamRedirExt},
        utils::{establish_tcp_tunnel, to_ipv4_mapped},
    },
};

mod sys;

/// Established Client Transparent Proxy
///
/// This method must be called after handshaking with client (for example, socks5 handshaking)
async fn establish_client_tcp_redir<'a>(
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    addr: &Address,
) -> io::Result<()> {
    let server = balancer.best_tcp_server();
    let svr_cfg = server.server_config();

    let mut remote = AutoProxyClientStream::connect(context, &server, addr).await?;

    establish_tcp_tunnel(svr_cfg, &mut stream, &mut remote, peer_addr, addr).await
}

async fn handle_redir_client(
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    s: TcpStream,
    peer_addr: SocketAddr,
    mut daddr: SocketAddr,
) -> io::Result<()> {
    // Get forward address from socket
    //
    // Try to convert IPv4 mapped IPv6 address for dual-stack mode.
    if let SocketAddr::V6(ref a) = daddr {
        if let Some(v4) = to_ipv4_mapped(a.ip()) {
            daddr = SocketAddr::new(IpAddr::from(v4), a.port());
        }
    }
    let target_addr = Address::from(daddr);
    establish_client_tcp_redir(context, balancer, s, peer_addr, &target_addr).await
}

pub async fn run_tcp_redir(
    context: Arc<ServiceContext>,
    client_config: &ServerAddr,
    balancer: PingBalancer,
    redir_ty: RedirType,
) -> io::Result<()> {
    let listener = match *client_config {
        ServerAddr::SocketAddr(ref saddr) => TcpListener::bind_redir(redir_ty, *saddr).await?,
        ServerAddr::DomainName(ref dname, port) => {
            lookup_then!(context.context_ref(), dname, port, |addr| {
                TcpListener::bind_redir(redir_ty, addr).await
            })?
            .1
        }
    };

    let listener = ShadowTcpListener::from_listener(listener, context.accept_opts());

    let actual_local_addr = listener.local_addr().expect("determine port bound to");

    info!(
        "shadowsocks TCP redirect ({}) listening on {}",
        redir_ty, actual_local_addr
    );

    loop {
        let (socket, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(err) => {
                error!("accept failed with error: {}", err);
                time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        trace!("got connection {}", peer_addr);

        let context = context.clone();
        let balancer = balancer.clone();
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

            if let Err(err) = handle_redir_client(context, balancer, socket, peer_addr, dst_addr).await {
                debug!("TCP redirect client, error: {:?}", err);
            }
        });
    }
}
