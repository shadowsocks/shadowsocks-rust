//! TLS transport used by HTTPS outbound proxy hops.
//!
//! Extracted from the previous `net::http_stream::ProxyHttpStream`. The two
//! TLS backends (`tokio-native-tls` / `tokio-rustls`) are mutually exclusive
//! and selected via Cargo features. When neither is enabled this module
//! exposes only the [`tls_unsupported`] helper that turns the request into
//! `io::ErrorKind::Unsupported`.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
use std::{
    pin::Pin,
    task::{self, Poll},
};

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
use pin_project::pin_project;
#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
use tokio::io::ReadBuf;

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
use super::stream::OutboundProxyStream;

/// Error helper for builds that disable both TLS backends.
#[inline]
pub fn tls_unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTPS outbound proxy requires either `local-http-native-tls` or `local-http-rustls` feature",
    ))
}

/// TLS-wrapped outbound proxy stream.
///
/// The inner I/O object is a boxed [`OutboundProxyStream`]. Boxing is purely
/// structural here: TLS libraries bake the inner type into their own
/// generics, so without indirection every additional TLS hop in a chain
/// would explode the type. There is **no** dynamic dispatch involved
/// (the `Box<OutboundProxyStream>` is a sized concrete enum value, not
/// `Box<dyn Trait>`).
#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
#[pin_project(project = OutboundTlsStreamProj)]
pub enum OutboundTlsStream {
    #[cfg(all(feature = "local-http-native-tls", not(feature = "local-http-rustls")))]
    NativeTls(#[pin] tokio_native_tls::TlsStream<Box<OutboundProxyStream>>, bool),
    #[cfg(feature = "local-http-rustls")]
    Rustls(#[pin] tokio_rustls::client::TlsStream<Box<OutboundProxyStream>>, bool),
}

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
impl OutboundTlsStream {
    /// Whether ALPN negotiated HTTP/2.
    pub fn negotiated_http2(&self) -> bool {
        match self {
            #[cfg(all(feature = "local-http-native-tls", not(feature = "local-http-rustls")))]
            Self::NativeTls(_, h2) => *h2,
            #[cfg(feature = "local-http-rustls")]
            Self::Rustls(_, h2) => *h2,
        }
    }
}

/// Establish a TLS session on top of an existing outbound proxy stream.
#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
pub async fn tls_connect(stream: OutboundProxyStream, domain: &str) -> io::Result<OutboundTlsStream> {
    tls_connect_inner(Box::new(stream), domain).await
}

#[cfg(all(feature = "local-http-native-tls", not(feature = "local-http-rustls")))]
async fn tls_connect_inner(
    stream: Box<OutboundProxyStream>,
    domain: &str,
) -> io::Result<OutboundTlsStream> {
    use native_tls::TlsConnector;

    let cx = TlsConnector::builder()
        .request_alpns(&["h2", "http/1.1"])
        .build()
        .map_err(|err| io::Error::other(format!("tls build: {err}")))?;
    let cx = tokio_native_tls::TlsConnector::from(cx);

    let s = cx
        .connect(domain, stream)
        .await
        .map_err(|err| io::Error::other(format!("tls connect: {err}")))?;

    let h2 = match s.get_ref().negotiated_alpn() {
        Ok(Some(alpn)) => alpn == b"h2",
        Ok(None) => false,
        Err(err) => return Err(io::Error::other(format!("tls alpn negotiate: {err}"))),
    };

    Ok(OutboundTlsStream::NativeTls(s, h2))
}

#[cfg(feature = "local-http-rustls")]
async fn tls_connect_inner(
    stream: Box<OutboundProxyStream>,
    domain: &str,
) -> io::Result<OutboundTlsStream> {
    use std::sync::{Arc, LazyLock};

    use log::warn;
    use rustls_native_certs::CertificateResult;
    use tokio_rustls::{
        TlsConnector,
        rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
    };

    static TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
        let mut config = ClientConfig::builder()
            .with_root_certificates({
                let mut store = RootCertStore::empty();
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

                let CertificateResult { certs, errors, .. } = rustls_native_certs::load_native_certs();
                if !errors.is_empty() {
                    for error in errors {
                        warn!("failed to load cert (native), error: {}", error);
                    }
                }

                for cert in certs {
                    if let Err(err) = store.add(cert) {
                        warn!("failed to add cert (native), error: {}", err);
                    }
                }

                store
            })
            .with_no_client_auth();

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    });

    let connector = TlsConnector::from(TLS_CONFIG.clone());

    let host = ServerName::try_from(domain)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid dnsname \"{domain}\"")))?
        .to_owned();

    let tls_stream = connector.connect(host, stream).await?;
    let (_, session) = tls_stream.get_ref();
    let h2 = matches!(session.alpn_protocol(), Some(b"h2"));

    Ok(OutboundTlsStream::Rustls(tls_stream, h2))
}

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
macro_rules! forward_call {
    ($self:expr, $method:ident $(, $param:expr)*) => {
        match $self.as_mut().project() {
            #[cfg(all(feature = "local-http-native-tls", not(feature = "local-http-rustls")))]
            OutboundTlsStreamProj::NativeTls(s, _) => s.$method($($param),*),
            #[cfg(feature = "local-http-rustls")]
            OutboundTlsStreamProj::Rustls(s, _) => s.$method($($param),*),
        }
    };
}

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
impl AsyncRead for OutboundTlsStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_read, cx, buf)
    }
}

#[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
impl AsyncWrite for OutboundTlsStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        forward_call!(self, poll_write, cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_flush, cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_shutdown, cx)
    }
}

// `S: AsyncRead + AsyncWrite` ensures the helper compiles without the TLS
// backends; otherwise the `_stream` parameter would be unused on TLS-disabled
// builds.
#[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
pub async fn tls_connect<S>(_stream: S, _domain: &str) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite,
{
    tls_unsupported()
}
