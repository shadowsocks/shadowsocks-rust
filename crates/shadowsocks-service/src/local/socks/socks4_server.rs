//! Shadowsocks SOCKS4/4a Local Server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use log::{debug, trace, warn};
use shadowsocks::{context::SharedContext, net::ConnectOpts};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
};

use crate::{
    local::{acl::AccessControl, loadbalancing::ServerIdent, net::AutoProxyClientStream, utils::establish_tcp_tunnel},
    net::FlowStat,
};

use super::socks4::{Address, Command, HandshakeRequest, HandshakeResponse, ResultCode};

pub struct Socks4 {
    context: SharedContext,
    flow_stat: Arc<FlowStat>,
    connect_opts: Arc<ConnectOpts>,
    nodelay: bool,
    acl: Option<Arc<AccessControl>>,
}

impl Socks4 {
    pub fn new(
        context: SharedContext,
        flow_stat: Arc<FlowStat>,
        connect_opts: Arc<ConnectOpts>,
        nodelay: bool,
        acl: Option<Arc<AccessControl>>,
    ) -> Socks4 {
        Socks4 {
            context,
            flow_stat,
            connect_opts,
            nodelay,
            acl,
        }
    }

    pub async fn handle_socks4_client(
        self,
        stream: TcpStream,
        server: Arc<ServerIdent>,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        // 1. Handshake

        // NOTE: Wraps it with BufReader for reading NULL terminated informations in HandshakeRequest
        let mut s = BufReader::new(stream);
        let handshake_req = HandshakeRequest::read_from(&mut s).await?;

        trace!("socks4 {:?}", handshake_req);

        match handshake_req.cd {
            Command::Connect => {
                debug!("CONNECT {}", handshake_req.dst);

                self.handle_socks4_connect(server, s, peer_addr, handshake_req.dst)
                    .await
            }
            Command::Bind => {
                warn!("BIND is not supported");

                let handshake_rsp = HandshakeResponse::new(ResultCode::RequestRejectedOrFailed);
                handshake_rsp.write_to(&mut s).await?;

                Ok(())
            }
        }
    }

    async fn handle_socks4_connect(
        self,
        server: Arc<ServerIdent>,
        mut stream: BufReader<TcpStream>,
        peer_addr: SocketAddr,
        target_addr: Address,
    ) -> io::Result<()> {
        let svr_cfg = server.server_config();
        let flow_stat = self.flow_stat;

        let target_addr = target_addr.into();

        let mut remote = match AutoProxyClientStream::connect_with_opts_acl_opt(
            self.context,
            &server,
            &target_addr,
            &self.connect_opts,
            flow_stat,
            &self.acl,
        )
        .await
        {
            Ok(remote) => {
                // Tell the client that we are ready
                let handshake_rsp = HandshakeResponse::new(ResultCode::RequestGranted);
                handshake_rsp.write_to(&mut stream).await?;

                trace!("sent header: {:?}", handshake_rsp);

                remote
            }
            Err(err) => {
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

        if self.nodelay {
            remote.set_nodelay(true)?;
        }

        // NOTE: Transfer all buffered data before unwrap, or these data will be lost
        let buffer = stream.buffer();
        if !buffer.is_empty() {
            remote.write_all(buffer).await?;
        }

        // UNWRAP.
        let mut stream = stream.into_inner();

        establish_tcp_tunnel(svr_cfg, &mut stream, remote, peer_addr, &target_addr).await
    }
}
