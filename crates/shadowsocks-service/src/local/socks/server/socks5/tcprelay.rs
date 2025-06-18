//! SOCKS5 TCP Server

use std::{
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    str,
    sync::Arc,
};

use log::{debug, error, trace, warn};
use shadowsocks::{
    ServerAddr,
    config::Mode,
    relay::socks5::{
        self, Address, Command, Error as Socks5Error, HandshakeRequest, HandshakeResponse, PasswdAuthRequest,
        PasswdAuthResponse, Reply, TcpRequestHeader, TcpResponseHeader,
    },
};
use tokio::net::TcpStream;

use crate::{
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::AutoProxyClientStream,
        socks::config::Socks5AuthConfig,
        utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
    },
    net::utils::ignore_until_end,
};

pub struct Socks5TcpHandler {
    context: Arc<ServiceContext>,
    udp_associate_addr: Arc<ServerAddr>,
    balancer: PingBalancer,
    mode: Mode,
    auth: Arc<Socks5AuthConfig>,
}

impl Socks5TcpHandler {
    pub fn new(
        context: Arc<ServiceContext>,
        udp_associate_addr: Arc<ServerAddr>,
        balancer: PingBalancer,
        mode: Mode,
        auth: Arc<Socks5AuthConfig>,
    ) -> Self {
        Self {
            context,
            udp_associate_addr,
            balancer,
            mode,
            auth,
        }
    }

    async fn check_auth(&self, stream: &mut TcpStream, handshake_req: &HandshakeRequest) -> io::Result<()> {
        use std::io::Error;

        let allow_none = !self.auth.auth_required();

        for method in handshake_req.methods.iter() {
            match *method {
                socks5::SOCKS5_AUTH_METHOD_PASSWORD => {
                    let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_PASSWORD);
                    trace!("reply handshake {:?}", resp);
                    resp.write_to(stream).await?;

                    return self.check_auth_password(stream).await;
                }
                socks5::SOCKS5_AUTH_METHOD_NONE => {
                    if !allow_none {
                        trace!("none authentication method is not allowed");
                    } else {
                        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
                        trace!("reply handshake {:?}", resp);
                        resp.write_to(stream).await?;

                        return Ok(());
                    }
                }
                _ => {
                    trace!("unsupported authentication method {}", method);
                }
            }
        }

        let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
        resp.write_to(stream).await?;

        trace!("reply handshake {:?}", resp);

        Err(Error::other(
            "currently shadowsocks-rust does not support authentication",
        ))
    }

    async fn check_auth_password(&self, stream: &mut TcpStream) -> io::Result<()> {
        use std::io::Error;

        const PASSWORD_AUTH_STATUS_FAILURE: u8 = 255;

        // Read initiation negotiation

        let req = match PasswdAuthRequest::read_from(stream).await {
            Ok(i) => i,
            Err(err) => {
                let rsp = PasswdAuthResponse::new(err.as_reply().as_u8());
                let _ = rsp.write_to(stream).await;

                return Err(Error::other(format!(
                    "Username/Password Authentication Initial request failed: {err}"
                )));
            }
        };

        let user_name = match str::from_utf8(&req.uname) {
            Ok(u) => u,
            Err(..) => {
                let rsp = PasswdAuthResponse::new(PASSWORD_AUTH_STATUS_FAILURE);
                let _ = rsp.write_to(stream).await;

                return Err(Error::other(
                    "Username/Password Authentication Initial request uname contains invalid characters",
                ));
            }
        };

        let password = match str::from_utf8(&req.passwd) {
            Ok(u) => u,
            Err(..) => {
                let rsp = PasswdAuthResponse::new(PASSWORD_AUTH_STATUS_FAILURE);
                let _ = rsp.write_to(stream).await;

                return Err(Error::other(
                    "Username/Password Authentication Initial request passwd contains invalid characters",
                ));
            }
        };

        if self.auth.passwd.check_user(user_name, password) {
            trace!(
                "socks5 authenticated with Username/Password method, user: {}, password: {}",
                user_name, password
            );

            let rsp = PasswdAuthResponse::new(0);
            rsp.write_to(stream).await?;

            Ok(())
        } else {
            let rsp = PasswdAuthResponse::new(PASSWORD_AUTH_STATUS_FAILURE);
            rsp.write_to(stream).await?;

            error!(
                "socks5 rejected Username/Password user: {}, password: {}",
                user_name, password
            );

            Err(Error::other(format!(
                "Username/Password Authentication failed, user: {user_name}, password: {password}"
            )))
        }
    }

    pub async fn handle_socks5_client(self, mut stream: TcpStream, peer_addr: SocketAddr) -> io::Result<()> {
        // 1. Handshake

        let handshake_req = match HandshakeRequest::read_from(&mut stream).await {
            Ok(r) => r,
            Err(Socks5Error::IoError(ref err)) if err.kind() == ErrorKind::UnexpectedEof => {
                trace!("socks5 handshake early eof. peer: {}", peer_addr);
                return Ok(());
            }
            Err(err) => {
                error!("socks5 handshake error: {}", err);
                return Err(err.into());
            }
        };

        trace!("socks5 {:?}", handshake_req);
        self.check_auth(&mut stream, &handshake_req).await?;

        // 2. Fetch headers
        let header = match TcpRequestHeader::read_from(&mut stream).await {
            Ok(h) => h,
            Err(err) => {
                error!("failed to get TcpRequestHeader: {}, peer: {}", err, peer_addr);
                let rh = TcpResponseHeader::new(err.as_reply(), Address::SocketAddress(peer_addr));
                rh.write_to(&mut stream).await?;
                return Err(err.into());
            }
        };

        trace!("socks5 {:?} peer: {}", header, peer_addr);

        let addr = header.address;

        // 3. Handle Command
        match header.command {
            Command::TcpConnect => {
                debug!("CONNECT {}", addr);

                self.handle_tcp_connect(stream, peer_addr, addr).await
            }
            Command::UdpAssociate => {
                debug!("UDP ASSOCIATE from {}", addr);

                self.handle_udp_associate(stream, addr).await
            }
            Command::TcpBind => {
                warn!("BIND is not supported");
                let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, addr);
                rh.write_to(&mut stream).await?;

                Ok(())
            }
        }
    }

    async fn handle_tcp_connect(
        self,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        target_addr: Address,
    ) -> io::Result<()> {
        if !self.mode.enable_tcp() {
            warn!("TCP CONNECT is disabled");

            let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, target_addr);
            rh.write_to(&mut stream).await?;

            return Ok(());
        }

        let mut server_opt = None;
        let remote_result = if self.balancer.is_empty() {
            AutoProxyClientStream::connect_bypassed(self.context.clone(), &target_addr).await
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

        let mut remote = match remote_result {
            Ok(remote) => {
                // Tell the client that we are ready
                let header =
                    TcpResponseHeader::new(socks5::Reply::Succeeded, Address::SocketAddress(remote.local_addr()?));
                header.write_to(&mut stream).await?;

                trace!("sent header: {:?}", header);

                remote
            }
            Err(err) => {
                let reply = match err.kind() {
                    ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                    ErrorKind::ConnectionAborted => Reply::HostUnreachable,
                    _ => Reply::NetworkUnreachable,
                };

                let dummy_address = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
                let header = TcpResponseHeader::new(reply, Address::SocketAddress(dummy_address));
                header.write_to(&mut stream).await?;

                return Err(err);
            }
        };

        match server_opt {
            Some(server) => {
                let svr_cfg = server.server_config();
                establish_tcp_tunnel(svr_cfg, &mut stream, &mut remote, peer_addr, &target_addr).await
            }
            None => establish_tcp_tunnel_bypassed(&mut stream, &mut remote, peer_addr, &target_addr).await,
        }
    }

    async fn handle_udp_associate(self, mut stream: TcpStream, client_addr: Address) -> io::Result<()> {
        if !self.mode.enable_udp() {
            warn!("socks5 udp is disabled");

            let rh = TcpResponseHeader::new(socks5::Reply::CommandNotSupported, client_addr);
            rh.write_to(&mut stream).await?;

            return Ok(());
        }

        // shadowsocks accepts both TCP and UDP from the same address

        let rh = TcpResponseHeader::new(socks5::Reply::Succeeded, self.udp_associate_addr.as_ref().into());
        rh.write_to(&mut stream).await?;

        // Hold connection until EOF.
        let _ = ignore_until_end(&mut stream).await;

        Ok(())
    }
}
