//! TCP client for SOCKS5 outbound connections

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{self, Poll},
};

use log::trace;
use shadowsocks::relay::socks5::{
    self, Address, Command, Error, HandshakeRequest, HandshakeResponse, PasswdAuthRequest, PasswdAuthResponse, Reply,
    TcpRequestHeader, TcpResponseHeader,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};

pub(crate) trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) type BoxProxyStream = Box<dyn ProxyStream>;

pub(crate) async fn socks5_handshake<S>(stream: &mut S, auth: Option<(&[u8], &[u8])>) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut methods = vec![socks5::SOCKS5_AUTH_METHOD_NONE];
    if auth.is_some() {
        methods.insert(0, socks5::SOCKS5_AUTH_METHOD_PASSWORD);
    }

    let hs = HandshakeRequest::new(methods);
    trace!("socks5 client connected, sending handshake: {:?}", hs);
    hs.write_to(stream).await?;

    let hsp = HandshakeResponse::read_from(stream).await?;
    trace!("socks5 handshake response: {:?}", hsp);

    match hsp.chosen_method {
        socks5::SOCKS5_AUTH_METHOD_NONE => Ok(()),
        socks5::SOCKS5_AUTH_METHOD_PASSWORD => {
            let (username, password) = auth.ok_or_else(|| {
                io::Error::other(
                    "SOCKS5 proxy requires username/password authentication, but no credentials were provided",
                )
            })?;

            let req = PasswdAuthRequest::new(username, password);
            req.write_to(stream).await?;

            let rsp = PasswdAuthResponse::read_from(stream).await?;
            if rsp.status == 0 {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "SOCKS5 username/password authentication failed with status {:#04x}",
                    rsp.status
                ))
                .into())
            }
        }
        method => Err(io::Error::other(format!(
            "SOCKS5 proxy selected unsupported authentication method {method:#04x}"
        ))
        .into()),
    }
}

pub(crate) async fn socks5_command<S, A>(stream: &mut S, command: Command, addr: A) -> Result<TcpResponseHeader, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Into<Address>,
{
    let header = TcpRequestHeader::new(command, addr.into());
    trace!("socks5 {command:?} request: {:?}", header);
    header.write_to(stream).await?;

    let response = TcpResponseHeader::read_from(stream).await?;
    trace!("socks5 {command:?} response: {:?}", response);
    match response.reply {
        Reply::Succeeded => Ok(response),
        reply => Err(Error::Reply(reply)),
    }
}

/// TCP client for SOCKS5 outbound connections.
pub struct Socks5TcpClient {
    stream: BoxProxyStream,
    local_addr: SocketAddr,
}

impl Socks5TcpClient {
    /// Connects to `addr` via SOCKS5 `proxy`
    pub async fn connect<A, P>(addr: A, proxy: P) -> Result<Self, Error>
    where
        A: Into<Address>,
        P: ToSocketAddrs,
    {
        let mut s = TcpStream::connect(proxy).await?;
        let local_addr = s.local_addr()?;
        socks5_handshake(&mut s, None).await?;
        socks5_command(&mut s, Command::TcpConnect, addr).await?;

        Ok(Self {
            stream: Box::new(s),
            local_addr,
        })
    }

    /// Negotiate SOCKS5 handshake and connect to `addr` on an existing stream (for proxy chains)
    pub async fn conduct_handshake_and_connect<S, A>(
        stream: &mut S,
        addr: A,
        auth: Option<(&[u8], &[u8])>,
    ) -> Result<(), Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        A: Into<Address>,
    {
        socks5_handshake(stream, auth).await?;
        socks5_command(stream, Command::TcpConnect, addr).await?;
        Ok(())
    }

    pub(crate) fn from_stream(stream: BoxProxyStream, local_addr: SocketAddr) -> Self {
        Self { stream, local_addr }
    }

    /// UDP Associate `addr` via SOCKS5 `proxy`
    ///
    /// `addr` is the address the UDP socket will send from (per RFC 1928)
    pub async fn udp_associate<A, P>(addr: A, proxy: P) -> Result<(Self, Address), Error>
    where
        A: Into<Address>,
        P: ToSocketAddrs,
    {
        let mut s = TcpStream::connect(proxy).await?;
        let local_addr = s.local_addr()?;
        socks5_handshake(&mut s, None).await?;
        let hp = socks5_command(&mut s, Command::UdpAssociate, addr).await?;

        Ok((
            Self {
                stream: Box::new(s),
                local_addr,
            },
            hp.address,
        ))
    }

    /// Returns the local socket address of the underlying connection
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// No-op: TCP_NODELAY cannot be set on a type-erased proxy stream after connect
    pub fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for Socks5TcpClient {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let stream = &mut self.get_mut().stream;
        Pin::new(&mut **stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Socks5TcpClient {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        let stream = &mut self.get_mut().stream;
        Pin::new(&mut **stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        let stream = &mut self.get_mut().stream;
        Pin::new(&mut **stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        let stream = &mut self.get_mut().stream;
        Pin::new(&mut **stream).poll_shutdown(cx)
    }
}
