//! Shared outbound proxy chain utilities.

use std::io;

use crate::config::{OutboundProxy, OutboundProxyProtocol};
use crate::net::{
    http_stream::ProxyHttpStream,
    socks5_client::{BoxProxyStream, Socks5TcpClient, socks5_command, socks5_handshake},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use shadowsocks::{
    context::Context,
    net::{ConnectOpts, TcpStream as OutboundTcpStream},
    relay::socks5::{Address, Command},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
async fn tls_wrap(stream: BoxProxyStream, host: &str) -> io::Result<BoxProxyStream> {
    let stream = ProxyHttpStream::connect_https(stream, host).await?;
    Ok(Box::new(stream))
}

#[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
async fn tls_wrap(_stream: BoxProxyStream, _host: &str) -> io::Result<BoxProxyStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTPS outbound proxy requires either local-http-native-tls or local-http-rustls feature",
    ))
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

pub(crate) async fn connect_via_proxy<S>(stream: &mut S, proxy: &OutboundProxy, target: &Address) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match proxy.protocol {
        OutboundProxyProtocol::Socks5 => {
            let auth = proxy
                .auth
                .as_ref()
                .map(|auth| (auth.username.as_bytes(), auth.password.as_bytes()));
            socks5_handshake(stream, auth).await.map_err(io::Error::other)?;
            socks5_command(stream, Command::TcpConnect, target.clone())
                .await
                .map_err(io::Error::other)?;
            Ok(())
        }
        OutboundProxyProtocol::Http | OutboundProxyProtocol::Https => http_connect(stream, proxy, target).await,
    }
}

pub(crate) async fn connect_chain_with_opts<A>(
    context: &Context,
    addr: A,
    proxies: &[OutboundProxy],
    opts: &ConnectOpts,
) -> Result<Socks5TcpClient, io::Error>
where
    A: Into<Address>,
{
    let Some(first_proxy) = proxies.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty outbound proxy chain",
        ));
    };

    let target_addr = addr.into();
    let first_proxy_addr = first_proxy.address();
    let first_stream = OutboundTcpStream::connect_remote_with_opts(context, &first_proxy_addr, opts).await?;
    let local_addr = first_stream.local_addr()?;
    let mut stream: BoxProxyStream = Box::new(first_stream);

    if first_proxy.protocol == OutboundProxyProtocol::Https {
        stream = tls_wrap(stream, &first_proxy.host).await?;
    }

    for (idx, proxy) in proxies.iter().enumerate() {
        if idx > 0 && proxy.protocol == OutboundProxyProtocol::Https {
            stream = tls_wrap(stream, &proxy.host).await?;
        }

        let next_target = proxies
            .get(idx + 1)
            .map(OutboundProxy::address)
            .unwrap_or_else(|| target_addr.clone());

        connect_via_proxy(&mut stream, proxy, &next_target).await?;
    }

    Ok(Socks5TcpClient::from_stream(stream, local_addr))
}
