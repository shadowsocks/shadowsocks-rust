//! UDP socket for communicating with shadowsocks' proxy server

#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, IntoRawSocket, RawSocket};
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::{Arc, LazyLock},
    task::{Context, Poll, ready},
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{Bytes, BytesMut};
use log::{info, trace, warn};
use tokio::{io::ReadBuf, time};

use crate::{
    config::{ServerAddr, ServerConfig, ServerUserManager},
    context::SharedContext,
    crypto::CipherKind,
    net::{AcceptOpts, ConnectOpts, UdpSocket as ShadowUdpSocket},
    relay::{socks5::Address, udprelay::options::UdpSocketControlData},
};

use super::{
    compat::{DatagramReceive, DatagramReceiveExt, DatagramSend, DatagramSendExt, DatagramSocket},
    crypto_io::{
        ProtocolError, ProtocolResult, decrypt_client_payload, decrypt_server_payload, encrypt_client_payload,
        encrypt_server_payload,
    },
};

static DEFAULT_CONNECT_OPTS: LazyLock<ConnectOpts> = LazyLock::new(Default::default);
static DEFAULT_SOCKET_CONTROL: LazyLock<UdpSocketControlData> = LazyLock::new(UdpSocketControlData::default);

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
    fn from(e: ProxySocketError) -> Self {
        match e {
            ProxySocketError::IoError(e) => e,
            _ => Self::other(e),
        }
    }
}

/// `ProxySocket` result type
pub type ProxySocketResult<T> = Result<T, ProxySocketError>;

/// UDP client for communicating with ShadowSocks' server
#[derive(Debug)]
pub struct ProxySocket<S> {
    socket_type: UdpSocketType,
    io: S,
    method: CipherKind,
    key: Box<[u8]>,
    send_timeout: Option<Duration>,
    recv_timeout: Option<Duration>,
    context: SharedContext,
    identity_keys: Arc<Vec<Bytes>>,
    user_manager: Option<Arc<ServerUserManager>>,
}

impl ProxySocket<ShadowUdpSocket> {
    /// Create a client to communicate with Shadowsocks' UDP server (outbound)
    pub async fn connect(context: SharedContext, svr_cfg: &ServerConfig) -> ProxySocketResult<Self> {
        Self::connect_with_opts(context, svr_cfg, &DEFAULT_CONNECT_OPTS).await
    }

    /// Create a client to communicate with Shadowsocks' UDP server (outbound)
    pub async fn connect_with_opts(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        opts: &ConnectOpts,
    ) -> ProxySocketResult<Self> {
        // Note: Plugins doesn't support UDP relay

        let socket = ShadowUdpSocket::connect_server_with_opts(&context, svr_cfg.udp_external_addr(), opts).await?;

        trace!(
            "connected udp remote {} (outbound: {}) with {:?}",
            svr_cfg.addr(),
            svr_cfg.udp_external_addr(),
            opts
        );

        Ok(Self::from_socket(UdpSocketType::Client, context, svr_cfg, socket))
    }

    /// Create a `ProxySocket` binding to a specific address (inbound)
    pub async fn bind(context: SharedContext, svr_cfg: &ServerConfig) -> ProxySocketResult<Self> {
        Self::bind_with_opts(context, svr_cfg, AcceptOpts::default()).await
    }

    /// Create a `ProxySocket` binding to a specific address (inbound)
    pub async fn bind_with_opts(
        context: SharedContext,
        svr_cfg: &ServerConfig,
        opts: AcceptOpts,
    ) -> ProxySocketResult<Self> {
        // Plugins doesn't support UDP
        let socket = match svr_cfg.udp_external_addr() {
            ServerAddr::SocketAddr(sa) => ShadowUdpSocket::listen_with_opts(sa, opts).await?,
            ServerAddr::DomainName(domain, port) => {
                lookup_then!(&context, domain, *port, |addr| {
                    ShadowUdpSocket::listen_with_opts(&addr, opts.clone()).await
                })?
                .1
            }
        };
        Ok(Self::from_socket(UdpSocketType::Server, context, svr_cfg, socket))
    }
}

impl<S> ProxySocket<S> {
    /// Create a `ProxySocket` from a I/O object that impls `DatagramTransport`
    pub fn from_socket(socket_type: UdpSocketType, context: SharedContext, svr_cfg: &ServerConfig, socket: S) -> Self {
        let key = svr_cfg.key().to_vec().into_boxed_slice();
        let method = svr_cfg.method();

        // NOTE: svr_cfg.timeout() is not for this socket, but for associations.
        Self {
            socket_type,
            io: socket,
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

    /// Set `send` timeout, `None` will clear timeout
    pub fn set_send_timeout(&mut self, t: Option<Duration>) {
        self.send_timeout = t;
    }

    /// Set `recv` timeout, `None` will clear timeout
    pub fn set_recv_timeout(&mut self, t: Option<Duration>) {
        self.recv_timeout = t;
    }
}

impl<S> ProxySocket<S>
where
    S: DatagramSend,
{
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
        self.send_with_ctrl(addr, &DEFAULT_SOCKET_CONTROL, payload).await
    }

    /// Send a UDP packet to addr through proxy with `ControlData`
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
            None => self.io.send(&send_buf).await?,
            Some(d) => match time::timeout(d, self.io.send(&send_buf)).await {
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

    /// poll family functions
    ///
    /// Send a UDP packet to addr through proxy
    ///
    /// NOTE: the `send_timeout` is ignored.
    pub fn poll_send(&self, addr: &Address, payload: &[u8], cx: &mut Context<'_>) -> Poll<ProxySocketResult<usize>> {
        self.poll_send_with_ctrl(addr, &DEFAULT_SOCKET_CONTROL, payload, cx)
    }

    /// poll family functions
    ///
    /// Send a UDP packet to addr through proxy with `ControlData`
    ///
    /// NOTE: the `send_timeout` is ignored.
    pub fn poll_send_with_ctrl(
        &self,
        addr: &Address,
        control: &UdpSocketControlData,
        payload: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<ProxySocketResult<usize>> {
        let mut send_buf = BytesMut::with_capacity(payload.len() + 256);

        self.encrypt_send_buffer(addr, control, &self.identity_keys, payload, &mut send_buf)?;

        trace!(
            "UDP server client send to {}, control: {:?}, payload length {} bytes, packet length {} bytes",
            addr,
            control,
            payload.len(),
            send_buf.len()
        );

        let n_send_buf = send_buf.len();

        match self.io.poll_send(cx, &send_buf).map_err(|x| x.into()) {
            Poll::Ready(Ok(l)) => {
                if l == n_send_buf {
                    Poll::Ready(Ok(payload.len()))
                } else {
                    Poll::Ready(Err(io::Error::from(ErrorKind::WriteZero).into()))
                }
            }
            x => x,
        }
    }

    /// poll family functions
    ///
    /// Send a UDP packet to addr through proxy `target`
    ///
    /// NOTE: the `send_timeout` is ignored.
    pub fn poll_send_to(
        &self,
        target: SocketAddr,
        addr: &Address,
        payload: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<ProxySocketResult<usize>> {
        self.poll_send_to_with_ctrl(target, addr, &DEFAULT_SOCKET_CONTROL, payload, cx)
    }

    /// poll family functions
    ///
    /// Send a UDP packet to addr through proxy `target` with `ControlData`
    ///
    /// NOTE: the `send_timeout` is ignored.
    pub fn poll_send_to_with_ctrl(
        &self,
        target: SocketAddr,
        addr: &Address,
        control: &UdpSocketControlData,
        payload: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<ProxySocketResult<usize>> {
        let mut send_buf = BytesMut::with_capacity(payload.len() + 256);

        self.encrypt_send_buffer(addr, control, &self.identity_keys, payload, &mut send_buf)?;

        info!(
            "UDP server client poll_send_to to {}, payload length {} bytes, packet length {} bytes",
            target,
            payload.len(),
            send_buf.len()
        );

        let n_send_buf = send_buf.len();
        match self.io.poll_send_to(cx, &send_buf, target).map_err(|x| x.into()) {
            Poll::Ready(Ok(l)) => {
                if l == n_send_buf {
                    Poll::Ready(Ok(payload.len()))
                } else {
                    Poll::Ready(Err(io::Error::from(ErrorKind::WriteZero).into()))
                }
            }
            x => x,
        }
    }

    /// poll family functions
    ///
    /// Check if socket is ready to `send`, or writable.
    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<ProxySocketResult<()>> {
        self.io.poll_send_ready(cx).map_err(|x| x.into())
    }

    /// Send a UDP packet to target through proxy `target`
    pub async fn send_to(&self, target: SocketAddr, addr: &Address, payload: &[u8]) -> ProxySocketResult<usize> {
        self.send_to_with_ctrl(target, addr, &DEFAULT_SOCKET_CONTROL, payload)
            .await
    }

    /// Send a UDP packet to target through proxy `target`
    pub async fn send_to_with_ctrl(
        &self,
        target: SocketAddr,
        addr: &Address,
        control: &UdpSocketControlData,
        payload: &[u8],
    ) -> ProxySocketResult<usize> {
        let mut send_buf = BytesMut::new();
        self.encrypt_send_buffer(addr, control, &self.identity_keys, payload, &mut send_buf)?;

        trace!(
            "UDP server client send_to to, addr {}, control: {:?}, payload length {} bytes, packet length {} bytes",
            addr,
            control,
            payload.len(),
            send_buf.len()
        );

        let send_len = match self.send_timeout {
            None => self.io.send_to(&send_buf, target).await?,
            Some(d) => match time::timeout(d, self.io.send_to(&send_buf, target)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        if send_buf.len() != send_len {
            warn!(
                "UDP server client send_to {} bytes, but actually sent {} bytes",
                send_buf.len(),
                send_len
            );
        }

        Ok(send_len)
    }
}

impl<S> ProxySocket<S>
where
    S: DatagramReceive,
{
    fn decrypt_recv_buffer(
        &self,
        recv_buf: &mut [u8],
        user_manager: Option<&ServerUserManager>,
    ) -> ProtocolResult<(usize, Address, Option<UdpSocketControlData>)> {
        match self.socket_type {
            UdpSocketType::Client => decrypt_server_payload(&self.context, self.method, &self.key, recv_buf),
            UdpSocketType::Server => {
                decrypt_client_payload(&self.context, self.method, &self.key, recv_buf, user_manager)
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
        let recv_n = match self.recv_timeout {
            None => self.io.recv(recv_buf).await?,
            Some(d) => match time::timeout(d, self.io.recv(recv_buf)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        let (n, addr, control) = match self.decrypt_recv_buffer(&mut recv_buf[..recv_n], self.user_manager.as_deref()) {
            Ok(x) => x,
            Err(err) => return Err(ProxySocketError::ProtocolError(err)),
        };

        trace!(
            "UDP server client receive from {}, control: {:?}, packet length {} bytes, payload length {} bytes",
            addr, control, recv_n, n
        );

        Ok((n, addr, recv_n, control))
    }

    /// Receive packet from Shadowsocks' UDP server
    ///
    /// This function will use `recv_buf` to store intermediate data, so it has to be big enough to store the whole shadowsocks' packet
    ///
    /// It is recommended to allocate a buffer to have at least 65536 bytes.
    #[allow(clippy::type_complexity)]
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
    #[allow(clippy::type_complexity)]
    pub async fn recv_from_with_ctrl(
        &self,
        recv_buf: &mut [u8],
    ) -> ProxySocketResult<(usize, SocketAddr, Address, usize, Option<UdpSocketControlData>)> {
        // Waiting for response from server SERVER -> CLIENT
        let (recv_n, target_addr) = match self.recv_timeout {
            None => self.io.recv_from(recv_buf).await?,
            Some(d) => match time::timeout(d, self.io.recv_from(recv_buf)).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        let (n, addr, control) = match self.decrypt_recv_buffer(&mut recv_buf[..recv_n], self.user_manager.as_deref()) {
            Ok(x) => x,
            Err(err) => return Err(ProxySocketError::ProtocolErrorWithPeer(target_addr, err)),
        };

        trace!(
            "UDP server client receive from {}, addr {}, control: {:?}, packet length {} bytes, payload length {} bytes",
            target_addr, addr, control, recv_n, n,
        );

        Ok((n, target_addr, addr, recv_n, control))
    }

    /// poll family functions.
    /// the recv_timeout is ignored.
    #[allow(clippy::type_complexity)]
    pub fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        recv_buf: &mut ReadBuf,
    ) -> Poll<ProxySocketResult<(usize, Address, usize)>> {
        self.poll_recv_with_ctrl(cx, recv_buf)
            .map(|r| r.map(|(n, a, rn, _)| (n, a, rn)))
    }

    /// poll family functions
    #[allow(clippy::type_complexity)]
    pub fn poll_recv_with_ctrl(
        &self,
        cx: &mut Context<'_>,
        recv_buf: &mut ReadBuf,
    ) -> Poll<ProxySocketResult<(usize, Address, usize, Option<UdpSocketControlData>)>> {
        ready!(self.io.poll_recv(cx, recv_buf))?;

        let n_recv = recv_buf.filled().len();

        match self.decrypt_recv_buffer(recv_buf.filled_mut(), self.user_manager.as_deref()) {
            Ok(x) => Poll::Ready(Ok((x.0, x.1, n_recv, x.2))),
            Err(err) => Poll::Ready(Err(ProxySocketError::ProtocolError(err))),
        }
    }

    /// poll family functions
    #[allow(clippy::type_complexity)]
    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        recv_buf: &mut ReadBuf,
    ) -> Poll<ProxySocketResult<(usize, SocketAddr, Address, usize)>> {
        self.poll_recv_from_with_ctrl(cx, recv_buf)
            .map(|r| r.map(|(n, sa, a, rn, _)| (n, sa, a, rn)))
    }

    /// poll family functions
    #[allow(clippy::type_complexity)]
    pub fn poll_recv_from_with_ctrl(
        &self,
        cx: &mut Context<'_>,
        recv_buf: &mut ReadBuf,
    ) -> Poll<ProxySocketResult<(usize, SocketAddr, Address, usize, Option<UdpSocketControlData>)>> {
        let src = ready!(self.io.poll_recv_from(cx, recv_buf))?;

        let n_recv = recv_buf.filled().len();
        match self.decrypt_recv_buffer(recv_buf.filled_mut(), self.user_manager.as_deref()) {
            Ok(x) => Poll::Ready(Ok((x.0, src, x.1, n_recv, x.2))),
            Err(err) => Poll::Ready(Err(ProxySocketError::ProtocolError(err))),
        }
    }

    /// poll family functions
    pub fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<ProxySocketResult<()>> {
        self.io.poll_recv_ready(cx).map_err(|x| x.into())
    }
}

impl<S> ProxySocket<S>
where
    S: DatagramSocket,
{
    /// Get local addr of socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

#[cfg(unix)]
impl<S> AsRawFd for ProxySocket<S>
where
    S: AsRawFd,
{
    /// Retrieve raw fd of the outbound socket
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}

#[cfg(unix)]
impl<S> AsFd for ProxySocket<S>
where
    S: AsFd,
{
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.io.as_fd()
    }
}

#[cfg(unix)]
impl<S> IntoRawFd for ProxySocket<S>
where
    S: IntoRawFd,
{
    fn into_raw_fd(self) -> RawFd {
        self.io.into_raw_fd()
    }
}

#[cfg(windows)]
impl<S> AsRawSocket for ProxySocket<S>
where
    S: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.io.as_raw_socket()
    }
}

#[cfg(windows)]
impl<S> AsSocket for ProxySocket<S>
where
    S: AsSocket,
{
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.io.as_socket()
    }
}

#[cfg(windows)]
impl<S> IntoRawSocket for ProxySocket<S>
where
    S: IntoRawSocket,
{
    fn into_raw_socket(self) -> RawSocket {
        self.io.into_raw_socket()
    }
}
