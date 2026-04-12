//! Shared outbound proxy chain utilities.

use std::io;

use crate::config::{OutboundProxy, OutboundProxyProtocol};
use crate::net::{
    http_connect::HttpConnectClient,
    http_stream::ProxyHttpStream,
    socks5_client::{BoxProxyStream, Socks5TcpClient},
};
use shadowsocks::{
    context::Context,
    net::{ConnectOpts, TcpStream as OutboundTcpStream},
    relay::socks5::Address,
};
use tokio::io::{AsyncRead, AsyncWrite};

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
            Socks5TcpClient::conduct_handshake_and_connect(stream, target.clone(), auth)
                .await
                .map_err(io::Error::other)
        }
        OutboundProxyProtocol::Http | OutboundProxyProtocol::Https => {
            let proxy_auth = proxy
                .auth
                .as_ref()
                .map(|auth| (auth.username.as_str(), auth.password.as_str()));
            HttpConnectClient::conduct_connect(stream, target, proxy_auth).await
        }
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
