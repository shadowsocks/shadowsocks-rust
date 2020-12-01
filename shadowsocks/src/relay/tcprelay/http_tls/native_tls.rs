//! TLS support by [native-tls](https://crates.io/crates/native-tls)

use std::{
    fs::File,
    future::Future,
    io::{self, Read},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use futures::{ready, FutureExt};
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, AddrStream},
};
use log::trace;
use native_tls::Identity;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::Config;

#[pin_project]
pub struct TlsAcceptor {
    acceptor: Arc<tokio_native_tls::TlsAcceptor>,
    #[pin]
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn bind(config: &Config, addr: &SocketAddr) -> io::Result<TlsAcceptor> {
        let id_path = config.tls_identity_path.as_ref().expect("identity path");
        let id_pwd = config.tls_identity_password.as_ref().expect("identify password");

        trace!("creating TLS acceptor with identity: {}", id_path.display());

        let mut id_file = File::open(id_path)?;
        let mut id_buf = Vec::new();
        id_file.read_to_end(&mut id_buf)?;

        let identity = match Identity::from_pkcs12(&id_buf, &id_pwd) {
            Ok(identity) => identity,
            Err(err) => {
                let err = io::Error::new(io::ErrorKind::Other, format!("load identity: {}", err));
                return Err(err);
            }
        };

        let acceptor = match native_tls::TlsAcceptor::new(identity) {
            Ok(acceptor) => acceptor,
            Err(err) => {
                let err = io::Error::new(io::ErrorKind::Other, format!("create tls acceptor: {}", err));
                return Err(err);
            }
        };

        Ok(TlsAcceptor {
            acceptor: Arc::new(From::from(acceptor)),
            incoming: match AddrIncoming::bind(addr) {
                Ok(incoming) => incoming,
                Err(err) => {
                    let err = io::Error::new(io::ErrorKind::Other, format!("hyper bind: {}", err));
                    return Err(err);
                }
            },
        })
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
                let acceptor = this.acceptor.clone();
                let remote_addr = stream.remote_addr();
                Poll::Ready(Some(Ok(TlsStream {
                    state: TlsStreamState::Handshaking(async move { acceptor.accept(stream).await }.boxed()),
                    remote_addr,
                })))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

enum TlsStreamState {
    Handshaking(
        Pin<
            Box<
                dyn Future<Output = Result<tokio_native_tls::TlsStream<AddrStream>, native_tls::Error>>
                    + Send
                    + 'static,
            >,
        >,
    ),
    Streaming(tokio_native_tls::TlsStream<AddrStream>),
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
                    let fut = accept_fut.as_mut();
                    match ready!(fut.poll($cx)) {
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
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
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
