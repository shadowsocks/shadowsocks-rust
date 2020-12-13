//! Shadowsocks SOCKS5 Local Server

use std::{
    io::{self, Cursor, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use futures::future::{self, AbortHandle};
use log::{debug, error, trace, warn};
use lru_time_cache::LruCache;
use shadowsocks::{
    context::SharedContext,
    lookup_then,
    net::ConnectOpts,
    relay::{
        socks5::{
            self,
            Address,
            Command,
            HandshakeRequest,
            HandshakeResponse,
            Reply,
            TcpRequestHeader,
            TcpResponseHeader,
            UdpAssociateHeader,
        },
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
    sync::Mutex,
    time,
};

use crate::{
    config::ClientConfig,
    local::{acl::AccessControl, loadbalancing::ServerIdent, net::AutoProxyClientStream, utils::establish_tcp_tunnel},
    net::{FlowStat, MonProxySocket},
};

pub struct Socks5 {
    context: SharedContext,
    flow_stat: Arc<FlowStat>,
    connect_opts: Arc<ConnectOpts>,
    nodelay: bool,
    acl: Option<Arc<AccessControl>>,
}

impl Socks5 {
    pub fn new(
        context: SharedContext,
        flow_stat: Arc<FlowStat>,
        connect_opts: Arc<ConnectOpts>,
        nodelay: bool,
        acl: Option<Arc<AccessControl>>,
    ) -> Socks5 {
        Socks5 {
            context,
            flow_stat,
            connect_opts,
            nodelay,
            acl,
        }
    }

    pub async fn handle_socks5_client(
        self,
        client_config: &ClientConfig,
        mut stream: TcpStream,
        server: Arc<ServerIdent>,
        peer_addr: SocketAddr,
    ) -> io::Result<()> {
        // 1. Handshake

        let handshake_req = HandshakeRequest::read_from(&mut stream).await?;

        trace!("socks5 {:?}", handshake_req);

        if !handshake_req.methods.contains(&socks5::SOCKS5_AUTH_METHOD_NONE) {
            use std::io::Error;

            let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE);
            resp.write_to(&mut stream).await?;

            return Err(Error::new(
                ErrorKind::Other,
                "currently shadowsocks-rust does not support authentication",
            ));
        } else {
            // Reply to client
            let resp = HandshakeResponse::new(socks5::SOCKS5_AUTH_METHOD_NONE);
            trace!("reply handshake {:?}", resp);
            resp.write_to(&mut stream).await?;
        }

        // 2. Fetch headers
        let header = match TcpRequestHeader::read_from(&mut stream).await {
            Ok(h) => h,
            Err(err) => {
                error!("failed to get TcpRequestHeader: {}", err);
                let rh = TcpResponseHeader::new(err.as_reply(), Address::SocketAddress(peer_addr));
                rh.write_to(&mut stream).await?;
                return Err(err.into());
            }
        };

        trace!("socks5 {:?}", header);

        let addr = header.address;

        // 3. Handle Command
        match header.command {
            Command::TcpConnect => {
                debug!("CONNECT {}", addr);

                self.handle_tcp_connect(stream, server, peer_addr, addr).await
            }
            Command::UdpAssociate => {
                debug!("UDP ASSOCIATE from {}", addr);

                self.handle_udp_associate(client_config, stream, server, addr).await
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
        server: Arc<ServerIdent>,
        peer_addr: SocketAddr,
        target_addr: Address,
    ) -> io::Result<()> {
        let svr_cfg = server.server_config();
        let flow_stat = self.flow_stat;

        let remote = match AutoProxyClientStream::connect_with_opts_acl_opt(
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

        if self.nodelay {
            remote.set_nodelay(true)?;
        }

        establish_tcp_tunnel(svr_cfg, &mut stream, remote, peer_addr, &target_addr).await
    }

    async fn handle_udp_associate(
        self,
        client_config: &ClientConfig,
        mut stream: TcpStream,
        server: Arc<ServerIdent>,
        client_addr: Address,
    ) -> io::Result<()> {
        let svr_cfg = server.server_config();

        let listener = match *client_config {
            ClientConfig::SocketAddr(ref saddr) => UdpSocket::bind(SocketAddr::new(saddr.ip(), 0)).await?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(&self.context, dname, port, |addr| {
                    UdpSocket::bind(SocketAddr::new(addr.ip(), 0)).await
                })?
                .1
            }
        };

        let client_socket = Arc::new(listener);

        // Establish a UDP association for client_addr, which must be a SocketAddr
        let client_addr = match client_addr {
            Address::SocketAddress(sa) => sa,
            Address::DomainNameAddress(dname, port) => {
                error!(
                    "UDP ASSOCIATE associates from a domain name address: {}:{}",
                    dname, port
                );
                let err = io::Error::new(
                    ErrorKind::InvalidInput,
                    "UDP ASSOCIATE associate from a domain name address",
                );
                return Err(err);
            }
        };

        // Connects to this address. The socket can only recv packets from this address.
        client_socket.connect(client_addr).await?;

        // Tell clients to send UDP packets to this socket
        let local_addr = client_socket.local_addr()?;

        let assoc = UdpAssociateRelayTask {
            context: self.context,
            client_socket,
            client_addr,
            server: server.clone(),
            connect_opts: self.connect_opts,
            remote_socket: None,
            remote_abortable: None,
            bypass_socket: None,
            bypass_abortable: None,
            acl: self.acl,
            bypass_addr_cache: Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(
                Duration::from_secs(5 * 60),
                256,
            ))),
            flow_stat: self.flow_stat,
        };
        let (relay_task, relay_abortable) = future::abortable(assoc.relay_task());
        tokio::spawn(relay_task);

        let rh = TcpResponseHeader::new(socks5::Reply::Succeeded, local_addr.into());
        rh.write_to(&mut stream).await?;

        debug!(
            "established udp association {} (inbound: {}) <-> {}",
            client_addr,
            local_addr,
            svr_cfg.addr(),
        );

        // Hold connection until EOF
        let mut buffer = [0u8; 2048];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(..) => continue,
                Err(..) => break,
            }
        }

        // Kills the task, and close stream and socket
        relay_abortable.abort();

        debug!(
            "udp association {} (inbound: {}) <-> {} finished",
            client_addr,
            local_addr,
            svr_cfg.addr(),
        );

        Ok(())
    }
}

struct UdpAssociateRelayTask {
    context: SharedContext,
    client_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    server: Arc<ServerIdent>,
    connect_opts: Arc<ConnectOpts>,
    remote_socket: Option<Arc<MonProxySocket>>,
    remote_abortable: Option<AbortHandle>,
    bypass_socket: Option<Arc<UdpSocket>>,
    bypass_abortable: Option<AbortHandle>,
    acl: Option<Arc<AccessControl>>,
    bypass_addr_cache: Arc<Mutex<LruCache<SocketAddr, Address>>>,
    flow_stat: Arc<FlowStat>,
}

impl Drop for UdpAssociateRelayTask {
    fn drop(&mut self) {
        if let Some(abortable) = self.remote_abortable.take() {
            abortable.abort();
        }

        if let Some(abortable) = self.bypass_abortable.take() {
            abortable.abort();
        }
    }
}

impl UdpAssociateRelayTask {
    async fn relay_task(mut self) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let n = match self.client_socket.recv(&mut buffer).await {
                Ok(n) => n,
                Err(err) => {
                    error!("UDP ASSOCIATE remote.recv() error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // PKT = UdpAssociateHeader + PAYLOAD
            let mut cur = Cursor::new(data);
            let header = match UdpAssociateHeader::read_from(&mut cur).await {
                Ok(h) => h,
                Err(..) => {
                    error!("received invalid UDP associate packet: {:?}", ByteStr::new(data));
                    continue;
                }
            };

            if header.frag != 0 {
                error!("received UDP associate with frag != 0, which is not supported by shadowsocks");
                continue;
            }

            let pos = cur.position() as usize;
            let payload = &data[pos..];

            trace!(
                "UDP ASSOCIATE {} -> {}, {} bytes",
                self.client_addr,
                header.address,
                payload.len()
            );

            let is_bypassed = match self.acl {
                None => false,
                Some(ref acl) => acl.check_target_bypassed(&self.context, &header.address).await,
            };

            if is_bypassed {
                if self.bypass_socket.is_none() {
                    // Create a socket (port) for bypassing packets

                    let bind_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0);
                    let socket = match UdpSocket::bind(bind_addr).await {
                        Ok(s) => s,
                        Err(err) => {
                            error!("failed to create bypass udp socket, error: {}", err);
                            continue;
                        }
                    };

                    trace!(
                        "created bypass socket binding to {} for client {}",
                        socket.local_addr()?,
                        self.client_addr
                    );

                    let bypass_socket = Arc::new(socket);

                    // Create remote-to-local copy task
                    let (task, abortable) = future::abortable(UdpAssociateRelayTask::r2l_task_bypassed(
                        self.client_socket.clone(),
                        self.client_addr,
                        bypass_socket.clone(),
                        self.bypass_addr_cache.clone(),
                    ));
                    tokio::spawn(task);

                    self.bypass_socket = Some(bypass_socket);
                    self.bypass_abortable = Some(abortable);
                }

                let socket = self
                    .bypass_socket
                    .as_deref()
                    .expect("unreachable. bypass udp socket is not created");

                let result = match header.address {
                    Address::SocketAddress(addr) => socket.send_to(payload, addr).await,
                    Address::DomainNameAddress(ref dname, port) => {
                        match lookup_then!(&self.context, dname, port, |target| {
                            socket.send_to(payload, target).await
                        }) {
                            Ok((resolved_addr, n)) => {
                                self.bypass_addr_cache
                                    .lock()
                                    .await
                                    .insert(resolved_addr, header.address.clone());

                                Ok(n)
                            }
                            Err(err) => Err(err),
                        }
                    }
                };

                if let Err(err) = result {
                    warn!(
                        "UDP ASSOCIATE {} -> {} (bypassed), {} bytes, error: {}",
                        self.client_addr,
                        header.address,
                        payload.len(),
                        err
                    );
                }
            } else {
                if self.remote_socket.is_none() {
                    // Create a socket (port) for remote packets
                    let svr_cfg = self.server.server_config();

                    // Connect to remote server
                    let remote_socket =
                        ProxySocket::connect_with_opts(self.context.clone(), svr_cfg, &self.connect_opts).await?;
                    let remote_socket = MonProxySocket::from_socket(remote_socket, self.flow_stat.clone());
                    let remote_socket = Arc::new(remote_socket);

                    trace!(
                        "created remote socket connecting to {} for client {}",
                        svr_cfg.addr(),
                        self.client_addr
                    );

                    // Create remote-to-local copy task
                    let (task, abortable) = future::abortable(UdpAssociateRelayTask::r2l_task_proxied(
                        self.client_socket.clone(),
                        self.client_addr,
                        remote_socket.clone(),
                    ));
                    tokio::spawn(task);

                    self.remote_socket = Some(remote_socket);
                    self.remote_abortable = Some(abortable);
                }

                let socket = self
                    .remote_socket
                    .as_deref()
                    .expect("unreachable. remote udp socket is not created");

                if let Err(err) = socket.send(&header.address, payload).await {
                    warn!(
                        "UDP ASSOCIATE {} -> {} (proxied), {} bytes, error: {}",
                        self.client_addr,
                        header.address,
                        payload.len(),
                        err
                    );
                }
            }
        }
    }

    async fn r2l_task_bypassed(
        client_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        remote_socket: Arc<UdpSocket>,
        addr_cache: Arc<Mutex<LruCache<SocketAddr, Address>>>,
    ) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut payload_buffer = BytesMut::new();
        loop {
            let (n, addr) = match remote_socket.recv_from(&mut buffer).await {
                Ok(n) => n,
                Err(err) => {
                    error!("UDP ASSOCIATE bypass.recv() error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];
            payload_buffer.clear();

            let remote_addr = match addr_cache.lock().await.get(&addr) {
                Some(a) => a.clone(),
                None => addr.into(),
            };

            let header = UdpAssociateHeader {
                frag: 0x00,
                address: remote_addr,
            };

            let header_len = header.serialized_len();
            payload_buffer.reserve(header_len + n);

            header.write_to_buf(&mut payload_buffer);
            payload_buffer.put_slice(data);

            trace!(
                "UDP ASSOCIATE {} <- {} (bypassed), {} bytes",
                client_addr,
                header.address,
                n
            );

            if let Err(err) = client_socket.send(&payload_buffer).await {
                warn!(
                    "UDP ASSOCIATE {} <- {} (bypassed), {} bytes, error: {}",
                    client_addr, header.address, n, err
                );
            }
        }
    }

    async fn r2l_task_proxied(
        client_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        remote_socket: Arc<MonProxySocket>,
    ) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut payload_buffer = BytesMut::new();
        loop {
            let (n, addr) = match remote_socket.recv(&mut buffer).await {
                Ok(n) => n,
                Err(err) => {
                    error!("UDP ASSOCIATE remote.recv() error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];
            payload_buffer.clear();

            let header = UdpAssociateHeader {
                frag: 0x00,
                address: addr,
            };

            let header_len = header.serialized_len();
            payload_buffer.reserve(header_len + n);

            header.write_to_buf(&mut payload_buffer);
            payload_buffer.put_slice(data);

            trace!(
                "UDP ASSOCIATE {} <- {} (proxied), {} bytes",
                client_addr,
                header.address,
                n
            );

            if let Err(err) = client_socket.send(&payload_buffer).await {
                warn!(
                    "UDP ASSOCIATE {} <- {} (proxied), {} bytes, error: {}",
                    client_addr, header.address, n, err
                );
            }
        }
    }
}
