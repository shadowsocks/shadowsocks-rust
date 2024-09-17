//! UDP socket for communicating with shadowsocks' proxy server

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    task::{ready, Context, Poll},
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{Bytes, BytesMut};
use futures::{
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream, StreamExt,
};
use log::{info, trace};
use once_cell::sync::Lazy;
use tokio::{io::ReadBuf, time};

use crate::{
    config::{ServerAddr, ServerConfig, ServerUserManager},
    context::SharedContext,
    crypto::CipherKind,
    net::{AcceptOpts, ConnectOpts, UdpSocket as ShadowUdpSocket},
    relay::{socks5::Address, udprelay::options::UdpSocketControlData},
};

use super::crypto_io::{
    decrypt_client_payload, decrypt_server_payload, encrypt_client_payload, encrypt_server_payload, ProtocolError,
    ProtocolResult,
};

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};

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

pub struct UdpPacket {
    pub data: Bytes,
    /// only available for recv
    pub src: Option<SocketAddr>,
    /// only used for send. None for bound socket
    pub dst: Option<SocketAddr>,
}

pub trait OutboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

impl<T, Item> OutboundDatagram<Item> for T where
    T: Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

pub type UdpIo = Box<dyn OutboundDatagram<UdpPacket>>;

/// UDP client for communicating with ShadowSocks' server
/// Thread safety: users of `ProxySocket` should not share it across threads
// TODO: unless a proper spinlock on `.socket` is implemented
#[derive(Debug)]
pub struct ProxySocket {
    socket_type: UdpSocketType,
    socket_w: tokio::sync::Mutex<SplitSink<UdpIo, UdpPacket>>,
    socket_r: tokio::sync::Mutex<SplitStream<UdpIo>>,
    // only used for server type socket to listen on
    local_addr: Option<SocketAddr>,
    #[cfg(unix)]
    fd: Option<RawFd>,
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

        let socket = ShadowUdpSocket::connect_server_with_opts(&context, svr_cfg.udp_external_addr(), opts).await?;

        trace!(
            "connected udp remote {} (outbound: {}) with {:?}",
            svr_cfg.addr(),
            svr_cfg.udp_external_addr(),
            opts
        );

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

        let socket: ShadowUdpSocket = socket.into();
        let local_addr = socket.local_addr().ok();
        #[cfg(unix)]
        let fd = socket.as_raw_fd();
        let io: UdpIo = Box::new(socket);
        let (socket_w, socket_r) = io.split();
        ProxySocket {
            socket_type,
            socket_w: socket_w.into(),
            socket_r: socket_r.into(),
            local_addr,
            #[cfg(unix)]
            fd: Some(fd),
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

    pub fn from_io(
        socket_type: UdpSocketType,
        context: SharedContext,
        svr_cfg: &ServerConfig,
        io: UdpIo,
        local_addr: Option<SocketAddr>,
        #[cfg(unix)] fd: Option<RawFd>,
    ) -> ProxySocket {
        let key = svr_cfg.key().to_vec().into_boxed_slice();
        let method = svr_cfg.method();

        // NOTE: svr_cfg.timeout() is not for this socket, but for associations.

        let (socket_w, socket_r) = io.split();
        ProxySocket {
            socket_type,
            socket_w: socket_w.into(),
            socket_r: socket_r.into(),
            local_addr,
            #[cfg(unix)]
            fd,
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
        let socket = match svr_cfg.udp_external_addr() {
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

        let n_sent = payload.len();

        let send_fn = || async {
            let mut socket = self.socket_w.lock().await;
            socket
                .send(UdpPacket {
                    data: send_buf.freeze(),
                    src: None,
                    dst: None,
                })
                .await
        };

        match self.send_timeout {
            None => send_fn().await?,
            Some(d) => match time::timeout(d, send_fn()).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        Ok(n_sent)
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

        let n_sent = payload.len();

        let mut io = self
            .socket_w
            .try_lock()
            .expect("no one else should be holding the lock");
        ready!(io.poll_ready_unpin(cx)?);
        io.start_send_unpin(UdpPacket {
            data: send_buf.freeze(),
            src: None,
            dst: None,
        })?;
        ready!(io.poll_flush_unpin(cx)?);

        Poll::Ready(Ok(n_sent))
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

        let n_sent = payload.len();
        let mut io = self
            .socket_w
            .try_lock()
            .expect("no one else should be holding the lock");
        ready!(io.poll_ready_unpin(cx)?);
        io.start_send_unpin(UdpPacket {
            data: send_buf.freeze(),
            src: None,
            dst: Some(target),
        })?;
        ready!(io.poll_flush_unpin(cx)?);
        Poll::Ready(Ok(n_sent))
    }

    /// poll family functions
    ///
    /// Check if socket is ready to `send`, or writable.
    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<ProxySocketResult<()>> {
        self.socket_w
            .try_lock()
            .expect("no one else should be holding the lock")
            .poll_ready_unpin(cx)
            .map_err(|x| x.into())
    }

    /// Send a UDP packet to target through proxy `target`
    pub async fn send_to(&self, target: SocketAddr, addr: &Address, payload: &[u8]) -> ProxySocketResult<usize> {
        self.send_to_with_ctrl(target, addr, &DEFAULT_SOCKET_CONTROL, payload)
            .await
            .map_err(Into::into)
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

        // we should not use `send_buf.len()` here, because `send_buf` may contain more data than `payload`
        let n_sent = payload.len();

        let send_fn = || async {
            let mut socket = self.socket_w.lock().await;
            socket
                .send(UdpPacket {
                    data: send_buf.freeze(),
                    src: None,
                    dst: target.into(),
                })
                .await
        };

        match self.send_timeout {
            None => send_fn().await?,
            Some(d) => match time::timeout(d, send_fn()).await {
                Ok(Ok(l)) => l,
                Ok(Err(err)) => return Err(err.into()),
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        };

        Ok(n_sent)
    }

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
        // Waiting for response from server SERVER -> CLIENT
        let pkt = match self.recv_timeout {
            None => self.socket_r.lock().await.next().await,
            Some(d) => match time::timeout(d, self.socket_r.lock().await.next()).await {
                Ok(l) => l,
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        }
        .ok_or(io::Error::from(ErrorKind::UnexpectedEof))?;

        // Copy data to recv_buf to decrypt and keep the original data touched
        recv_buf[..pkt.data.len()].copy_from_slice(&pkt.data);

        let (n, addr, control) =
            match self.decrypt_recv_buffer(&mut recv_buf[..pkt.data.len()], self.user_manager.as_deref()) {
                Ok(x) => x,
                Err(err) => return Err(ProxySocketError::ProtocolError(err)),
            };

        trace!(
            "UDP server client receive from {}, control: {:?}, packet length {} bytes, payload length {} bytes",
            addr,
            control,
            pkt.data.len(),
            n
        );

        Ok((n, addr, pkt.data.len(), control))
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
        let pkt = match self.recv_timeout {
            None => self.socket_r.lock().await.next().await,
            Some(d) => match time::timeout(d, self.socket_r.lock().await.next()).await {
                Ok(l) => l,
                Err(..) => return Err(io::Error::from(ErrorKind::TimedOut).into()),
            },
        }
        .ok_or(io::Error::from(ErrorKind::UnexpectedEof))?;

        let recv_n = pkt.data.len();
        // Copy data to recv_buf to decrypt and keep the original data touched
        recv_buf[..recv_n].copy_from_slice(&pkt.data);

        let target_addr = pkt.src.expect("src should be present");

        let (n, addr, control) = match self.decrypt_recv_buffer(&mut recv_buf[..recv_n], self.user_manager.as_deref()) {
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
        let data = ready!(self
            .socket_r
            .try_lock()
            .expect("no one else should be holding the lock")
            .poll_next_unpin(cx))
        .ok_or(io::Error::from(ErrorKind::UnexpectedEof))?;

        recv_buf.put_slice(&data.data);

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
        let data = ready!(self
            .socket_r
            .try_lock()
            .expect("no one else should be holding the lock")
            .poll_next_unpin(cx))
        .ok_or(io::Error::from(ErrorKind::UnexpectedEof))?;
        let src = data.src.expect("src should be present");
        recv_buf.put_slice(&data.data);

        let n_recv = recv_buf.filled().len();
        match self.decrypt_recv_buffer(recv_buf.filled_mut(), self.user_manager.as_deref()) {
            Ok(x) => Poll::Ready(Ok((x.0, src, x.1, n_recv, x.2))),
            Err(err) => Poll::Ready(Err(ProxySocketError::ProtocolError(err))),
        }
    }

    /// poll family functions
    pub fn poll_recv_ready(&self, _: &mut Context<'_>) -> Poll<ProxySocketResult<()>> {
        Poll::Ready(Ok(()))
    }

    /// Get local addr of socket
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "local addr not available"))
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

#[cfg(unix)]
impl AsRawFd for ProxySocket {
    /// Retrieve raw fd of the outbound socket
    fn as_raw_fd(&self) -> RawFd {
        self.fd.unwrap_or_else(|| {
            log::warn!("the proxy socket is an abstract socket, raw fd is not available");
            -1
        })
    }
}
