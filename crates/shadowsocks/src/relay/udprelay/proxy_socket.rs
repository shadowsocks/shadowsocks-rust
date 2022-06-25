//! UDP socket for communicating with shadowsocks' proxy server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{Bytes, BytesMut};
use log::{trace, warn};
use once_cell::sync::Lazy;
use tokio::{net::ToSocketAddrs, time};

use crate::{
    config::{ServerAddr, ServerConfig, ServerUserManager},
    context::SharedContext,
    crypto::CipherKind,
    net::{AcceptOpts, ConnectOpts, UdpSocket as ShadowUdpSocket},
    relay::{socks5::Address, udprelay::options::UdpSocketControlData},
};

use super::crypto_io::{
    decrypt_client_payload,
    decrypt_server_payload,
    encrypt_client_payload,
    encrypt_server_payload,
    ProtocolError,
    ProtocolResult,
};

static DEFAULT_CONNECT_OPTS: Lazy<ConnectOpts> = Lazy::new(Default::default);
static DEFAULT_SOCKET_CONTROL: Lazy<UdpSocketControlData> = Lazy::new(UdpSocketControlData::default);

/// UDP socket type, defining whether the socket is used in Client or Server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketType {
    /// Socket used for `Client -> Server`
    Client,
    /// Socket used for `Server -> Client`
    Server,
}

/// `ProxySocket` error type
#[derive(thiserror::Error, Debug)]
pub enum ProxySocketError {
    /// std::io::Error
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ProtocolError(ProtocolError),
    #[error("peer: {0}, {1}")]
    ProtocolErrorWithPeer(SocketAddr, ProtocolError),
    #[error("invalid server user identity {:?}", ByteStr::new(.0))]
    InvalidServerUser(Bytes),
}

impl From<ProxySocketError> for io::Error {
    fn from(e: ProxySocketError) -> io::Error {
        match e {
            ProxySocketError::IoError(e) => e,
            _ => io::Error::new(ErrorKind::Other, e),
        }
    }
}

/// `ProxySocket` result type
pub type ProxySocketResult<T> = Result<T, ProxySocketError>;

/// UDP client for communicating with ShadowSocks' server
pub struct ProxySocket {
    socket_type: UdpSocketType,
    socket: ShadowUdpSocket,
    method: CipherKind,
    key: Box<[u8]>,
    send_timeout: Option<Duration>,
    recv_timeout: Option<Duration>,
    context: SharedContext,
    identity_keys: Arc<Vec<Bytes>>,
    user_manager: Option<Arc<ServerUserManager>>,
}

impl ProxySocket {
    /// Create a client to communicate with Shadowsocks' UDP server (outbound)
    pub async fn connect(context: SharedContext, svr_cfg: &ServerConfig) -> ProxySocketResult<ProxySocket> {
        ProxySocket::connect_with_opts(context, svr_cfg, &DEFAULT_CONNECT_OPTS)
            .await
            .map_err(Into::into)
    }

    /// Create a client to communicate with Shadowsocks' UDP server (outbound)
    pub async fn connect_with_opts(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        opts: &ConnectOpts,
    ) -> ProxySocketResult<ProxySocket> {
        // Note: Plugins doesn't support UDP relay

        let socket = ShadowUdpSocket::connect_server_with_opts(&context, svr_cfg.addr(), opts).await?;

        trace!("connected udp remote {} with {:?}", svr_cfg.addr(), opts);

        Ok(ProxySocket::from_socket(
            UdpSocketType::Client,
            context,
            svr_cfg,
            socket,
        ))
    }

    /// Create a `ProxySocket` from a `UdpSocket`
    pub fn from_socket<S>(
        socket_type: UdpSocketType,
        context: SharedContext,
        svr_cfg: &ServerConfig,
        socket: S,
    ) -> ProxySocket
    where
        S: Into<ShadowUdpSocket>,
    {
        let key = svr_cfg.key().to_vec().into_boxed_slice();
        let method = svr_cfg.method();

        // NOTE: svr_cfg.timeout() is not for this socket, but for associations.

        ProxySocket {
            socket_type,
            socket: socket.into(),
            method,
            key,
            send_timeout: None,
            recv_timeout: None,
            context,
            identity_keys: match socket_type {
                UdpSocketType::Client => svr_cfg.clone_identity_keys(),
                UdpSocketType::Server => Arc::new(Vec::new()),
            },
            user_manager: match socket_type {
                UdpSocketType::Client => None,
                UdpSocketType::Server => svr_cfg.clone_user_manager(),
            },
        }
    }

    /// Create a `ProxySocket` binding to a specific address (inbound)
    pub async fn bind(context: SharedContext, svr_cfg: &ServerConfig) -> ProxySocketResult<ProxySocket> {
        ProxySocket::bind_with_opts(context, svr_cfg, AcceptOpts::default())
            .await
            .map_err(Into::into)
    }

    /// Create a `ProxySocket` binding to a specific address (inbound)
    pub async fn bind_with_opts(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        opts: AcceptOpts,
    ) -> ProxySocketResult<ProxySocket> {
        // Plugins doesn't support UDP
        let socket = match svr_cfg.addr() {
            ServerAddr::SocketAddr(sa) => ShadowUdpSocket::listen_with_opts(sa, opts).await?,
            ServerAddr::DomainName(domain, port) => {
                lookup_then!(&context, domain, *port, |addr| {
                    ShadowUdpSocket::listen_with_opts(&addr, opts.clone()).await
                })?
                .1
            }
        };
        Ok(ProxySocket::from_socket(
            UdpSocketType::Server,
            context,
            svr_cfg,
            socket,
        ))
    }

    fn encrypt_send_buffer(
        &self,
        addr: &Address,
        control: &UdpSocketControlData,
        identity_keys: &[Bytes],
        payload: &[u8],
        send_buf: &mut BytesMut,
    ) -> ProxySocketResult<()> {
        match self.socket_type {
            UdpSocketType::Client => encrypt_client_payload(
                &self.context,
                self.method,
                &self.key,
                addr,
                control,
                identity_keys,
                payload,
                send_buf,
            ),
            UdpSocketType::Server => {
                let mut key = self.key.as_ref();

                if let Some(ref user) = control.user {
                    trace!("udp encrypt with {:?} identity", user);
                    key = user.key();
                }

                encrypt_server_payload(&self.context, self.method, key, addr, control, payload, send_buf)
            }
        }

        Ok(())
    }

    /// Send a UDP packet to addr through proxy
    #[inline]
    pub async fn send(&self, addr: &Address, payload: &[u8]) -> ProxySocketResult<usize> {
        self.send_with_ctrl(addr, &DEFAULT_SOCKET_CONTROL, payload)
            .await
            .map_err(Into::into)
    }

    /// Send a UDP packet to addr through proxy
    pub async fn send_with_ctrl(
        &self,
        addr: &Address,
        control: &UdpSocketControlData,
        payload: &[u8],
    ) -> ProxySocketResult<usize> {
        let mut send_buf = BytesMut::new();
        self.encrypt_send_buffer(addr, control, &self.identity_keys, payload, &mut send_buf)?;

        trace!(
            "UDP server client send to {}, control: {:?}, payload length {} bytes, packet length {} bytes",
            addr,
            control,
            payload.len(),
            send_buf.len()
        );

        let send_len = match self.send_timeout {
            None => self.socket.send(&send_buf).await?,
            Some(d) => match time::timeout(d, self.socket.send(&send_buf)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        if send_buf.len() != send_len {
            warn!(
                "UDP server client send {} bytes, but actually sent {} bytes",
                send_buf.len(),
                send_len
            );
        }

        Ok(send_len)
    }

    /// Send a UDP packet to target from proxy
    pub async fn send_to<A: ToSocketAddrs>(
        &self,
        target: A,
        addr: &Address,
        payload: &[u8],
    ) -> ProxySocketResult<usize> {
        self.send_to_with_ctrl(target, addr, &DEFAULT_SOCKET_CONTROL, payload)
            .await
            .map_err(Into::into)
    }

    /// Send a UDP packet to target from proxy
    pub async fn send_to_with_ctrl<A: ToSocketAddrs>(
        &self,
        target: A,
        addr: &Address,
        control: &UdpSocketControlData,
        payload: &[u8],
    ) -> ProxySocketResult<usize> {
        let mut send_buf = BytesMut::new();
        self.encrypt_send_buffer(addr, control, &self.identity_keys, payload, &mut send_buf)?;

        trace!(
            "UDP server client send to, addr {}, control: {:?}, payload length {} bytes, packet length {} bytes",
            addr,
            control,
            payload.len(),
            send_buf.len()
        );

        let send_len = match self.send_timeout {
            None => self.socket.send_to(&send_buf, target).await?,
            Some(d) => match time::timeout(d, self.socket.send_to(&send_buf, target)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        if send_buf.len() != send_len {
            warn!(
                "UDP server client send {} bytes, but actually sent {} bytes",
                send_buf.len(),
                send_len
            );
        }

        Ok(send_len)
    }

    async fn decrypt_recv_buffer(
        &self,
        recv_buf: &mut [u8],
        user_manager: Option<&ServerUserManager>,
    ) -> ProtocolResult<(usize, Address, Option<UdpSocketControlData>)> {
        match self.socket_type {
            UdpSocketType::Client => decrypt_server_payload(&self.context, self.method, &self.key, recv_buf).await,
            UdpSocketType::Server => {
                decrypt_client_payload(&self.context, self.method, &self.key, recv_buf, user_manager).await
            }
        }
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    pub async fn recv(&self, recv_buf: &mut [u8]) -> ProxySocketResult<(usize, Address, usize)> {
        self.recv_with_ctrl(recv_buf).await.map(|(n, a, rn, _)| (n, a, rn))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    pub async fn recv_with_ctrl(
        &self,
        recv_buf: &mut [u8],
    ) -> ProxySocketResult<(usize, Address, usize, Option<UdpSocketControlData>)> {
        // Waiting for response from server SERVER -> CLIENT
        let recv_n = match self.recv_timeout {
            None => self.socket.recv(recv_buf).await?,
            Some(d) => match time::timeout(d, self.socket.recv(recv_buf)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        let (n, addr, control) = match self
            .decrypt_recv_buffer(&mut recv_buf[..recv_n], self.user_manager.as_deref())
            .await
        {
            Ok(x) => x,
            Err(err) => return Err(ProxySocketError::ProtocolError(err)),
        };

        trace!(
            "UDP server client receive from {}, control: {:?}, packet length {} bytes, payload length {} bytes",
            addr,
            control,
            recv_n,
            n
        );

        Ok((n, addr, recv_n, control))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    pub async fn recv_from(&self, recv_buf: &mut [u8]) -> ProxySocketResult<(usize, SocketAddr, Address, usize)> {
        self.recv_from_with_ctrl(recv_buf)
            .await
            .map(|(n, sa, a, rn, _)| (n, sa, a, rn))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    pub async fn recv_from_with_ctrl(
        &self,
        recv_buf: &mut [u8],
    ) -> ProxySocketResult<(usize, SocketAddr, Address, usize, Option<UdpSocketControlData>)> {
        // Waiting for response from server SERVER -> CLIENT
        let (recv_n, target_addr) = match self.recv_timeout {
            None => self.socket.recv_from(recv_buf).await?,
            Some(d) => match time::timeout(d, self.socket.recv_from(recv_buf)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        let (n, addr, control) = match self
            .decrypt_recv_buffer(&mut recv_buf[..recv_n], self.user_manager.as_deref())
            .await
        {
            Ok(x) => x,
            Err(err) => return Err(ProxySocketError::ProtocolErrorWithPeer(target_addr, err)),
        };

        trace!(
            "UDP server client receive from {}, addr {}, control: {:?}, packet length {} bytes, payload length {} bytes",
            target_addr,
            addr,
            control,
            recv_n,
            n,
        );

        Ok((n, target_addr, addr, recv_n, control))
    }

    /// Get local addr of socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Set `send` timeout, `None` will clear timeout
    pub fn set_send_timeout(&mut self, t: Option<Duration>) {
        self.send_timeout = t;
    }

    /// Set `recv` timeout, `None` will clear timeout
    pub fn set_recv_timeout(&mut self, t: Option<Duration>) {
        self.recv_timeout = t;
    }
}
