//! Proxied HTTP stream

use std::{
    io::{self, ErrorKind},
    pin::Pin,
    task::{self, Poll},
};

use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::local::net::AutoProxyClientStream;

#[allow(clippy::large_enum_variant)]
#[pin_project(project = ProxyHttpStreamProj)]
pub enum ProxyHttpStream {
    Http(#[pin] AutoProxyClientStream),
    #[cfg(feature = "local-http-native-tls")]
    Https(#[pin] tokio_native_tls::TlsStream<AutoProxyClientStream>, bool),
    #[cfg(feature = "local-http-rustls")]
    Https(#[pin] tokio_rustls::client::TlsStream<AutoProxyClientStream>, bool),
}

impl ProxyHttpStream {
    pub fn connect_http(stream: AutoProxyClientStream) -> ProxyHttpStream {
        ProxyHttpStream::Http(stream)
    }

    #[cfg(feature = "local-http-native-tls")]
    pub async fn connect_https(stream: AutoProxyClientStream, domain: &str) -> io::Result<ProxyHttpStream> {
        use native_tls::TlsConnector;

        let cx = match TlsConnector::builder().request_alpns(&["h2", "http/1.1"]).build() {
            Ok(c) => c,
            Err(err) => {
                return Err(io::Error::new(ErrorKind::Other, format!("tls build: {err}")));
            }
        };
        let cx = tokio_native_tls::TlsConnector::from(cx);

        match cx.connect(domain, stream).await {
            Ok(s) => {
                let negotiated_h2 = match s.get_ref().negotiated_alpn() {
                    Ok(Some(alpn)) => alpn == b"h2",
                    Ok(None) => false,
                    Err(err) => {
                        let ierr = io::Error::new(ErrorKind::Other, format!("tls alpn negotiate: {err}"));
                        return Err(ierr);
                    }
                };

                Ok(ProxyHttpStream::Https(s, negotiated_h2))
            }
            Err(err) => {
                let ierr = io::Error::new(ErrorKind::Other, format!("tls connect: {err}"));
                Err(ierr)
            }
        }
    }

    #[cfg(feature = "local-http-rustls")]
    pub async fn connect_https(stream: AutoProxyClientStream, domain: &str) -> io::Result<ProxyHttpStream> {
        use log::warn;
        use once_cell::sync::Lazy;
        use rustls_native_certs::CertificateResult;
        use std::sync::Arc;
        use tokio_rustls::{
            rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
            TlsConnector,
        };

        static TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
            let mut config = ClientConfig::builder()
                .with_root_certificates({
                    // Load WebPKI roots (Mozilla's root certificates)
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

            // Try to negotiate HTTP/2
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        });

        let connector = TlsConnector::from(TLS_CONFIG.clone());

        let host = match ServerName::try_from(domain) {
            Ok(n) => n,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid dnsname \"{domain}\""),
                ));
            }
        };

        let tls_stream = connector.connect(host.to_owned(), stream).await?;

        let (_, session) = tls_stream.get_ref();
        let negotiated_http2 = matches!(session.alpn_protocol(), Some(b"h2"));

        Ok(ProxyHttpStream::Https(tls_stream, negotiated_http2))
    }

    #[cfg(not(any(feature = "local-http-native-tls", feature = "local-http-rustls")))]
    pub async fn connect_https(_stream: AutoProxyClientStream, _domain: &str) -> io::Result<ProxyHttpStream> {
        let err = io::Error::new(
            ErrorKind::Other,
            "https is not supported, consider enable it by feature \"local-http-native-tls\" or \"local-http-rustls\"",
        );
        Err(err)
    }

    pub fn negotiated_http2(&self) -> bool {
        match *self {
            ProxyHttpStream::Http(..) => false,
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            ProxyHttpStream::Https(_, n) => n,
        }
    }
}

macro_rules! forward_call {
    ($self:expr, $method:ident $(, $param:expr)*) => {
        match $self.as_mut().project() {
            ProxyHttpStreamProj::Http(stream) => stream.$method($($param),*),
            #[cfg(any(feature = "local-http-native-tls", feature = "local-http-rustls"))]
            ProxyHttpStreamProj::Https(stream, ..) => stream.$method($($param),*),
        }
    };
}

impl AsyncRead for ProxyHttpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        forward_call!(self, poll_read, cx, buf)
    }
}

impl AsyncWrite for ProxyHttpStream {
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
