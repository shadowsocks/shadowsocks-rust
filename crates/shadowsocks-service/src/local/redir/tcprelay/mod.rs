//! Shadowsocks TCP transparent proxy

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use log::{debug, error, info, trace};
use shadowsocks::{ServerAddr, lookup_then, net::TcpListener as ShadowTcpListener, relay::socks5::Address};
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
        utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
    },
    net::utils::to_ipv4_mapped,
};

#[allow(unused_imports)]
mod sys;

/// Established Client Transparent Proxy
///
/// This method must be called after handshaking with client (for example, socks5 handshaking)
async fn establish_client_tcp_redir(
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    addr: &Address,
) -> io::Result<()> {
    if balancer.is_empty() {
        let mut remote = AutoProxyClientStream::connect_bypassed(context, addr).await?;
        return establish_tcp_tunnel_bypassed(&mut stream, &mut remote, peer_addr, addr).await;
    }

    let server = balancer.best_tcp_server();
    let svr_cfg = server.server_config();

    let mut remote =
        AutoProxyClientStream::connect_with_opts(context, &server, addr, server.connect_opts_ref()).await?;

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

/// Redir TCP server instance
pub struct RedirTcpServer {
    context: Arc<ServiceContext>,
    listener: TcpListener,
    balancer: PingBalancer,
    redir_ty: RedirType,
}

impl RedirTcpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        client_config: &ServerAddr,
        balancer: PingBalancer,
        redir_ty: RedirType,
    ) -> io::Result<Self> {
        let listener = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                TcpListener::bind_redir(redir_ty, *saddr, context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, port, |addr| {
                    TcpListener::bind_redir(redir_ty, addr, context.accept_opts()).await
                })?
                .1
            }
        };

        Ok(Self {
            context,
            listener,
            balancer,
            redir_ty,
        })
    }

    /// Get server local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(self) -> io::Result<()> {
        let listener = ShadowTcpListener::from_listener(self.listener, self.context.accept_opts())?;

        let actual_local_addr = listener.local_addr().expect("determine port bound to");

        info!(
            "shadowsocks TCP redirect ({}) listening on {}",
            self.redir_ty, actual_local_addr
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

            let context = self.context.clone();
            let balancer = self.balancer.clone();
            let redir_ty = self.redir_ty;
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
}
