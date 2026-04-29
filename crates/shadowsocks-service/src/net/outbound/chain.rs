//! Outbound proxy chain construction.

use std::io;

use log::trace;
use shadowsocks::relay::socks5::Address;

use super::{
    OutboundProxyClient, OutboundProxyHop, OutboundProxyKind, TcpDialer, socks5::Socks5Negotiator,
    stream::OutboundProxyStream,
};

#[cfg(feature = "local-http")]
use super::http_connect::HttpConnectClient;

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
use super::tls::tls_connect;

impl OutboundProxyClient {
    /// Establish a TCP tunnel to `target` through the configured proxy
    /// chain. The first hop is dialled through `dialer`, allowing each
    /// caller to inject its own connect-options policy (`ConnectOpts`,
    /// bypass routing, ...).
    pub async fn connect_tcp<D>(
        &self,
        dialer: &D,
        target: &Address,
    ) -> io::Result<OutboundProxyStream>
    where
        D: TcpDialer + Sync,
    {
        connect_chain(self.hops(), dialer, target).await
    }
}

pub(crate) async fn connect_chain<D>(
    hops: &[OutboundProxyHop],
    dialer: &D,
    target: &Address,
) -> io::Result<OutboundProxyStream>
where
    D: TcpDialer + Sync,
{
    let Some(first_hop) = hops.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty outbound proxy chain",
        ));
    };

    trace!("dialling first outbound proxy hop {}", first_hop.addr);
    let first_tcp = dialer.dial(&first_hop.addr).await?;
    let mut stream = OutboundProxyStream::from_tcp(first_tcp)?;

    for (idx, hop) in hops.iter().enumerate() {
        // For HTTPS hops, wrap the wire layer with TLS *before* speaking
        // the application-level CONNECT verb.
        if hop.is_https() {
            stream = tls_wrap(stream, hop.tls_sni()).await?;
        }

        let next_target = hops
            .get(idx + 1)
            .map(|h| &h.addr)
            .unwrap_or(target);

        stream = negotiate_hop(stream, hop, next_target).await?;
    }

    Ok(stream)
}

async fn negotiate_hop(
    mut stream: OutboundProxyStream,
    hop: &OutboundProxyHop,
    next_target: &Address,
) -> io::Result<OutboundProxyStream> {
    match &hop.kind {
        OutboundProxyKind::Socks5 { auth } => {
            Socks5Negotiator::establish_tcp(&mut stream, next_target.clone(), auth)
                .await
                .map_err(io::Error::other)?;
            Ok(stream)
        }
        #[cfg(feature = "local-http")]
        OutboundProxyKind::Http { auth } | OutboundProxyKind::Https { auth, .. } => {
            let local_addr = stream.local_addr()?;
            let tunnel = HttpConnectClient::establish(stream, next_target, auth).await?;
            Ok(OutboundProxyStream::from_http(local_addr, tunnel))
        }
        #[cfg(not(feature = "local-http"))]
        OutboundProxyKind::Http { .. } | OutboundProxyKind::Https { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "HTTP/HTTPS outbound proxy requires the `local-http` feature",
        )),
    }
}

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
async fn tls_wrap(stream: OutboundProxyStream, sni: &str) -> io::Result<OutboundProxyStream> {
    let local_addr = stream.local_addr()?;
    let tls = tls_connect(stream, sni).await?;
    Ok(OutboundProxyStream::from_tls(local_addr, tls))
}

#[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
async fn tls_wrap(_stream: OutboundProxyStream, _sni: &str) -> io::Result<OutboundProxyStream> {
    super::tls::tls_unsupported()
}
