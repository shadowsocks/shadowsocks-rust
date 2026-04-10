//! TCP client for outbound proxy connections

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{self, Poll},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use log::trace;
use shadowsocks::{
    context::Context,
    net::{ConnectOpts, TcpStream as OutboundTcpStream},
    relay::socks5::{
        self, Address, Command, Error, HandshakeRequest, HandshakeResponse, PasswdAuthRequest, PasswdAuthResponse, Reply,
        TcpRequestHeader, TcpResponseHeader,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};

use crate::{
    config::{OutboundProxy, OutboundProxyAuth, OutboundProxyProtocol},
    net::http_stream::ProxyHttpStream,
};

trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

type BoxProxyStream = Box<dyn ProxyStream>;

pub(crate) fn address_authority(addr: &Address) -> String {
    match addr {
        Address::SocketAddress(sa) => {
            if sa.is_ipv6() {
                format!("[{}]:{}", sa.ip(), sa.port())
            } else {
                sa.to_string()
            }
        }
        Address::DomainNameAddress(host, port) => format!("{host}:{port}"),
    }
}

async fn tls_wrap(stream: BoxProxyStream, host: &str) -> io::Result<BoxProxyStream> {
    let stream = ProxyHttpStream::connect_https(stream, host).await?;
    Ok(Box::new(stream))
}

pub(crate) async fn socks5_handshake<S>(stream: &mut S, auth: Option<&OutboundProxyAuth>) -> Result<(), Error>
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
            let auth = auth.ok_or_else(|| {
                io::Error::other(
                    "SOCKS5 proxy requires username/password authentication, but no credentials were provided",
                )
            })?;

            let req = PasswdAuthRequest::new(auth.username.as_bytes(), auth.password.as_bytes());
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

pub(crate) async fn http_connect<S>(stream: &mut S, proxy: &OutboundProxy, target: &Address) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = address_authority(target);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n");

    if let Some(ref auth) = proxy.auth {
        let encoded = BASE64_STANDARD.encode(format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }

    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];

    let header_end = loop {
        if response.len() > 16 * 1024 {
            return Err(io::Error::other("HTTP CONNECT response header is too large"));
        }

        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading HTTP CONNECT response",
            ));
        }

        response.extend_from_slice(&buf[..n]);
        if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let header = String::from_utf8_lossy(&response[..header_end]);
    let status_line = header.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("invalid HTTP CONNECT response: {status_line}")))?;

    if status_code != 200 {
        return Err(io::Error::other(format!(
            "HTTP CONNECT proxy rejected tunnel with status {status_code}: {status_line}"
        )));
    }

    Ok(())
}

async fn connect_via_proxy(stream: &mut BoxProxyStream, proxy: &OutboundProxy, target: &Address) -> io::Result<()> {
    match proxy.protocol {
        OutboundProxyProtocol::Socks5 => {
            socks5_handshake(stream, proxy.auth.as_ref())
                .await
                .map_err(io::Error::other)?;
            socks5_command(stream, Command::TcpConnect, target.clone())
                .await
                .map_err(io::Error::other)?;
            Ok(())
        }
        OutboundProxyProtocol::Http | OutboundProxyProtocol::Https => http_connect(stream, proxy, target).await,
    }
}

/// TCP client for outbound proxy chains
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

    /// Connects to `addr` via an outbound proxy chain
    pub async fn connect_chain<A>(addr: A, proxies: &[OutboundProxy]) -> Result<Self, Error>
    where
        A: Into<Address>,
    {
        let Some(first_proxy) = proxies.first() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty outbound proxy chain").into());
        };

        let target_addr = addr.into();
        let first_stream = TcpStream::connect((first_proxy.host.as_str(), first_proxy.port)).await?;
        let local_addr = first_stream.local_addr()?;
        let mut stream: BoxProxyStream = Box::new(first_stream);

        for (idx, proxy) in proxies.iter().enumerate() {
            let next_target = proxies
                .get(idx + 1)
                .map(OutboundProxy::address)
                .unwrap_or_else(|| target_addr.clone());

            if proxy.protocol == OutboundProxyProtocol::Https {
                stream = tls_wrap(stream, &proxy.host).await.map_err(Error::from)?;
            }

            connect_via_proxy(&mut stream, proxy, &next_target)
                .await
                .map_err(Error::from)?;
        }

        Ok(Self { stream, local_addr })
    }

    /// Connects to `addr` via an outbound proxy chain, using shadowsocks connect options
    /// for the first outbound hop.
    pub async fn connect_chain_with_opts<A>(
        context: &Context,
        addr: A,
        proxies: &[OutboundProxy],
        opts: &ConnectOpts,
    ) -> Result<Self, Error>
    where
        A: Into<Address>,
    {
        let Some(first_proxy) = proxies.first() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty outbound proxy chain").into());
        };

        let target_addr = addr.into();
        let first_proxy_addr = first_proxy.address();
        let first_stream = OutboundTcpStream::connect_remote_with_opts(context, &first_proxy_addr, opts).await?;
        let local_addr = first_stream.local_addr()?;
        let mut stream: BoxProxyStream = Box::new(first_stream);

        for (idx, proxy) in proxies.iter().enumerate() {
            let next_target = proxies
                .get(idx + 1)
                .map(OutboundProxy::address)
                .unwrap_or_else(|| target_addr.clone());

            if proxy.protocol == OutboundProxyProtocol::Https {
                stream = tls_wrap(stream, &proxy.host).await.map_err(Error::from)?;
            }

            connect_via_proxy(&mut stream, proxy, &next_target)
                .await
                .map_err(Error::from)?;
        }

        Ok(Self { stream, local_addr })
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

        Ok((Self { stream: Box::new(s), local_addr }, hp.address))
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
