//! Shadowsocks SOCKS4/4a Local Server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use log::{debug, error, trace, warn};
use shadowsocks::config::Mode;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpStream,
};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::AutoProxyClientStream,
    utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
};

use crate::local::socks::socks4::{
    Address, Command, Error as Socks4Error, HandshakeRequest, HandshakeResponse, ResultCode,
};

pub struct Socks4TcpHandler {
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    mode: Mode,
}

impl Socks4TcpHandler {
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer, mode: Mode) -> Socks4TcpHandler {
        Socks4TcpHandler {
            context,
            balancer,
            mode,
        }
    }

    pub async fn handle_socks4_client(self, stream: TcpStream, peer_addr: SocketAddr) -> io::Result<()> {
        // 1. Handshake

        // NOTE: Wraps it with BufReader for reading NULL terminated information in HandshakeRequest
        let mut s = BufReader::new(stream);
        let handshake_req = match HandshakeRequest::read_from(&mut s).await {
            Ok(r) => r,
            Err(Socks4Error::IoError(ref err)) if err.kind() == ErrorKind::UnexpectedEof => {
                trace!("socks4 handshake early eof. peer: {}", peer_addr);
                return Ok(());
            }
            Err(err) => {
                error!("socks4 handshake error: {}", err);
                return Err(err.into());
            }
        };

        trace!("socks4 {:?} peer: {}", handshake_req, peer_addr);

        match handshake_req.cd {
            Command::Connect => {
                debug!("CONNECT {}", handshake_req.dst);

                self.handle_socks4_connect(s, peer_addr, handshake_req.dst).await
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
        mut stream: BufReader<TcpStream>,
        peer_addr: SocketAddr,
        target_addr: Address,
    ) -> io::Result<()> {
        if !self.mode.enable_tcp() {
            warn!("TCP CONNECT is disabled");

            let handshake_rsp = HandshakeResponse::new(ResultCode::RequestRejectedOrFailed);
            handshake_rsp.write_to(&mut stream).await?;

            return Ok(());
        }

        let target_addr = target_addr.into();
        let mut server_opt = None;
        let server_result = if self.balancer.is_empty() {
            AutoProxyClientStream::connect_bypassed(self.context, &target_addr).await
        } else {
            let server = self.balancer.best_tcp_server();

            let r = AutoProxyClientStream::connect_with_opts(
                self.context,
                &server,
                &target_addr,
                server.connect_opts_ref(),
            )
            .await;
            server_opt = Some(server);

            r
        };

        let mut remote = match server_result {
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

        // NOTE: Transfer all buffered data before unwrap, or these data will be lost
        let buffer = stream.buffer();
        if !buffer.is_empty() {
            remote.write_all(buffer).await?;
        }

        // UNWRAP.
        let mut stream = stream.into_inner();

        match server_opt {
            Some(server) => {
                let svr_cfg = server.server_config();
                establish_tcp_tunnel(svr_cfg, &mut stream, &mut remote, peer_addr, &target_addr).await
            }
            None => establish_tcp_tunnel_bypassed(&mut stream, &mut remote, peer_addr, &target_addr).await,
        }
    }
}
