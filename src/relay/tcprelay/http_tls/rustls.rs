//! TLS support by [rustls](https://crates.io/crates/rustls)

use std::{
    fs::File,
    future::Future,
    io::{self, BufReader, Read},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use futures::ready;
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, AddrStream},
};
use log::trace;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{self, NoClientAuth, PrivateKey, ServerConfig};

use crate::config::Config;

#[pin_project]
pub struct TlsAcceptor {
    acceptor: tokio_rustls::TlsAcceptor,
    #[pin]
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn bind(config: &Config, addr: &SocketAddr) -> io::Result<TlsAcceptor> {
        let id_cert_path = config.tls_identity_certificate_path.as_ref().expect("certificate path");
        let id_key_path = config.tls_identity_private_key_path.as_ref().expect("private key path");

        trace!(
            "creating TLS acceptor with cert: {}, private key: {}",
            id_cert_path.display(),
            id_key_path.display()
        );

        let id_cert_file = File::open(id_cert_path)?;
        let id_cert = match rustls::internal::pemfile::certs(&mut BufReader::new(id_cert_file)) {
            Ok(certs) => certs,
            Err(..) => {
                let err = io::Error::new(io::ErrorKind::InvalidData, "error while loading certificates");
                return Err(err);
            }
        };

        let mut id_key_file = File::open(id_key_path)?;
        let mut id_key_buf = Vec::new();
        id_key_file.read_to_end(&mut id_key_buf)?;

        let mut id_key = TlsAcceptor::load_pkcs8_private_key(&id_key_buf)?;
        if id_key.is_empty() {
            id_key = TlsAcceptor::load_rsa_private_key(&id_key_buf)?;
        }

        if id_key.is_empty() {
            let err = io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot find any PKCS #8 or RSA private keys",
            );
            return Err(err);
        }

        let mut config = ServerConfig::new(NoClientAuth::new());
        if let Err(err) = config.set_single_cert(id_cert, id_key.remove(0)) {
            let err = io::Error::new(io::ErrorKind::Other, format!("setting certificate: {}", err));
            return Err(err);
        }
        config.set_protocols(&["h2".into(), "http/1.1".into()]);

        let server_config = Arc::new(config);

        Ok(TlsAcceptor {
            acceptor: From::from(server_config),
            incoming: match AddrIncoming::bind(addr) {
                Ok(incoming) => incoming,
                Err(err) => {
                    let err = io::Error::new(io::ErrorKind::Other, format!("hyper bind: {}", err));
                    return Err(err);
                }
            },
        })
    }

    fn load_pkcs8_private_key(key: &[u8]) -> io::Result<Vec<PrivateKey>> {
        match rustls::internal::pemfile::pkcs8_private_keys(&mut BufReader::new(key)) {
            Ok(pk) => Ok(pk),
            Err(..) => {
                let err = io::Error::new(io::ErrorKind::InvalidData, "error while loading PKCS #8 private keys");
                Err(err)
            }
        }
    }

    fn load_rsa_private_key(key: &[u8]) -> io::Result<Vec<PrivateKey>> {
        match rustls::internal::pemfile::rsa_private_keys(&mut BufReader::new(key)) {
            Ok(pk) => Ok(pk),
            Err(..) => {
                let err = io::Error::new(io::ErrorKind::InvalidData, "error while loading PKCS #8 private keys");
                Err(err)
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.incoming.local_addr()
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let this = self.project();
        match ready!(this.incoming.poll_accept(cx)) {
            Some(Ok(stream)) => {
                let remote_addr = stream.remote_addr();
                Poll::Ready(Some(Ok(TlsStream {
                    state: TlsStreamState::Handshaking(this.acceptor.accept(stream)),
                    remote_addr,
                })))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

enum TlsStreamState {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

pub struct TlsStream {
    state: TlsStreamState,
    remote_addr: SocketAddr,
}

impl TlsStream {
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

macro_rules! forward_stream_method {
    ($self:expr, $cx:expr, $method:ident $(, $param:expr)*) => {{
        let this = $self.get_mut();

        loop {
            match this.state {
                TlsStreamState::Handshaking(ref mut accept_fut) => {
                    match ready!(Pin::new(accept_fut).poll($cx)) {
                        Ok(stream) => {
                            this.state = TlsStreamState::Streaming(stream);
                        }
                        Err(err) => {
                            let err = io::Error::new(io::ErrorKind::Other, format!("tls handshake: {}", err));
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                TlsStreamState::Streaming(ref mut stream) => {
                    return Pin::new(stream).$method($cx, $($param),*);
                }
            }
        }
    }};
}

impl AsyncRead for TlsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        forward_stream_method!(self, cx, poll_read, buf)
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        forward_stream_method!(self, cx, poll_write, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.state {
            TlsStreamState::Handshaking(..) => Poll::Ready(Ok(())),
            TlsStreamState::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.state {
            TlsStreamState::Handshaking(..) => Poll::Ready(Ok(())),
            TlsStreamState::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
