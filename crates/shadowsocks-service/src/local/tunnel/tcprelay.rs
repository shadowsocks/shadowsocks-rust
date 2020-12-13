//! TCP Tunnel Server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use log::{error, info, trace};
use shadowsocks::{
    config::ServerConfig,
    context::SharedContext,
    lookup_then,
    net::ConnectOpts,
    relay::socks5::Address,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time,
};

use crate::{
    config::ClientConfig,
    local::{
        loadbalancing::{PingBalancerBuilder, ServerIdent, ServerType as BalancerServerType},
        net::AutoProxyClientStream,
        utils::establish_tcp_tunnel,
    },
    net::FlowStat,
};

pub struct TcpTunnel {
    context: SharedContext,
    flow_stat: Arc<FlowStat>,
    connect_opts: Arc<ConnectOpts>,
    nodelay: bool,
}

impl TcpTunnel {
    pub fn new(
        context: SharedContext,
        flow_stat: Arc<FlowStat>,
        connect_opts: Arc<ConnectOpts>,
        nodelay: bool,
    ) -> TcpTunnel {
        TcpTunnel {
            context,
            flow_stat,
            connect_opts,
            nodelay,
        }
    }

    pub async fn run(
        self,
        client_config: &ClientConfig,
        servers: Vec<ServerConfig>,
        forward_addr: &Address,
    ) -> io::Result<()> {
        let listener = match *client_config {
            ClientConfig::SocketAddr(ref saddr) => TcpListener::bind(saddr).await?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(&self.context, dname, port, |addr| { TcpListener::bind(addr).await })?.1
            }
        };

        info!("shadowsocks tcp tunnel listening on {}", client_config);

        let mut balancer_builder =
            PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Tcp, self.connect_opts.clone());

        for server in servers {
            let server_ident = ServerIdent::new(server, ());
            balancer_builder.add_server(server_ident);
        }

        let (balancer, checker) = balancer_builder.build();
        tokio::spawn(checker);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if self.nodelay {
                let _ = stream.set_nodelay(true);
            }

            let server = balancer.best_server();
            let context = self.context.clone();
            let connect_opts = self.connect_opts.clone();
            let forward_addr = forward_addr.clone();
            let flow_stat = self.flow_stat.clone();
            let nodelay = self.nodelay;

            tokio::spawn(TcpTunnel::handle_tcp_client(
                context,
                stream,
                server,
                peer_addr,
                forward_addr,
                connect_opts,
                flow_stat,
                nodelay,
            ));
        }
    }

    async fn handle_tcp_client(
        context: SharedContext,
        mut stream: TcpStream,
        server: Arc<ServerIdent>,
        peer_addr: SocketAddr,
        forward_addr: Address,
        connect_opts: Arc<ConnectOpts>,
        flow_stat: Arc<FlowStat>,
        nodelay: bool,
    ) -> io::Result<()> {
        let svr_cfg = server.server_config();
        trace!(
            "establishing tcp tunnel {} <-> {} through sever {} (outbound: {})",
            peer_addr,
            forward_addr,
            svr_cfg.external_addr(),
            svr_cfg.addr(),
        );

        let remote =
            AutoProxyClientStream::connect_with_opts(context, &server, &forward_addr, &connect_opts, flow_stat).await?;

        if nodelay {
            remote.set_nodelay(true)?;
        }

        establish_tcp_tunnel(svr_cfg, &mut stream, remote.into(), peer_addr, &forward_addr).await
    }
}
