//! A `ProxyStream` that bypasses or proxies data through proxy server automatically

use std::{
    io::{self, ErrorKind, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use bytes::{BufMut, BytesMut};
use httparse::{Response, Status};
use log::warn;
use pin_project::pin_project;
use shadowsocks::{
    net::{ConnectOpts, TcpStream},
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    local::{context::ServiceContext, loadbalancing::ServerIdent},
    net::MonProxyStream,
};
pub struct BasicAuth(pub String);
use super::auto_proxy_io::AutoProxyIo;

/// Unified stream for bypassed and proxied connections
#[allow(clippy::large_enum_variant)]
#[pin_project(project = AutoProxyClientStreamProj)]
pub enum AutoProxyClientStream {
    Proxied(#[pin] ProxyClientStream<MonProxyStream<TcpStream>>),
    #[cfg(feature = "https-tunnel")]
    HttpTunnel(#[pin] HttpTunnelStream),
    Bypassed(#[pin] TcpStream),
}
#[cfg(feature = "https-tunnel")]
#[pin_project]
pub struct HttpTunnelStream {
    #[pin]
    stream: tokio_rustls::client::TlsStream<shadowsocks::net::TcpStream>,
    addr: Address,
    auth: String,
}
// #[cfg(feature = "https-tunnel")]
// static CONNECTOR: LazyLock<tokio_rustls::TlsConnector> = std::sync::LazyLock::new(|| {
//     use log::warn;
//     use once_cell::sync::Lazy;
//     use std::sync::Arc;
//     use tokio_rustls::{
//         rustls::{ClientConfig, RootCertStore},
//         TlsConnector,
//     };

//     static TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
//         let mut config = ClientConfig::builder()
//             .with_root_certificates(match rustls_native_certs::load_native_certs() {
//                 Ok(certs) => {
//                     let mut store = RootCertStore::empty();

//                     for cert in certs {
//                         if let Err(err) = store.add(cert) {
//                             warn!("failed to add cert (native), error: {}", err);
//                         }
//                     }

//                     store
//                 }
//                 Err(err) => {
//                     warn!("failed to load native certs, {}, going to load from webpki-roots", err);

//                     let mut store = RootCertStore::empty();
//                     store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

//                     store
//                 }
//             })
//             .with_no_client_auth();

//         // Try to negotiate HTTP/2
//         config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
//         Arc::new(config)
//     });

//     TlsConnector::from(TLS_CONFIG.clone())
// });
#[cfg(feature = "https-tunnel")]
impl HttpTunnelStream {
    pub async fn handshake(&mut self) -> io::Result<()> {
        let addr = self.addr.clone();
        let auth = self.auth.clone();
        let mut stream = &mut self.stream;
        connect_tunnel(addr, stream, &auth).await?;
        wait_response(&mut stream).await?;
        Ok(())
    }
}

impl AutoProxyClientStream {
    pub async fn handshake_tunnel(&mut self) -> io::Result<()> {
        match self {
            AutoProxyClientStream::Proxied(_) => Ok(()),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(tunnel_stream) => {
                tunnel_stream.handshake().await?;
                Ok(())
            }
            AutoProxyClientStream::Bypassed(_) => Ok(()),
        }
    }
    pub fn auth(&self) -> Option<BasicAuth> {
        match self {
            AutoProxyClientStream::Proxied(_) => None,
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(tunnel_stream) => Some(BasicAuth(tunnel_stream.auth.clone())),
            AutoProxyClientStream::Bypassed(_) => None,
        }
    }
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        AutoProxyClientStream::connect_with_opts(context.clone(), server, addr, context.connect_opts_ref()).await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        opts: &ConnectOpts,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        let addr = addr.into();
        if context.check_target_bypassed(&addr).await {
            AutoProxyClientStream::connect_bypassed_with_opts(context, addr, opts).await
        } else {
            #[cfg(feature = "https-tunnel")]
            {
                AutoProxyClientStream::connect_http_tunnel(context, server, addr).await
            }
            #[cfg(not(feature = "https-tunnel"))]
            AutoProxyClientStream::connect_proxied_with_opts(context, server, addr, opts).await
        }
    }

    #[cfg(feature = "https-tunnel")]
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_http_tunnel<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        let _flow_stat = context.flow_stat();
        let stream = TcpStream::connect_server_with_opts(
            context.context_ref(),
            server.server_config().tcp_external_addr(),
            context.connect_opts_ref(),
        )
        .await?;

        use log::warn;
        use once_cell::sync::Lazy;
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

                    if let Ok(certs) = rustls_native_certs::load_native_certs() {
                        for cert in certs {
                            if let Err(err) = store.add(cert) {
                                warn!("failed to add cert (native), error: {}", err);
                            }
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
        let host = match ServerName::try_from(server.server_config().addr().host()) {
            Ok(n) => n,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid dnsname \"{}\"", server.server_config().addr().host()),
                ));
            }
        };
        let tls_stream = connector.connect(host.to_owned(), stream).await?;

        Ok(AutoProxyClientStream::HttpTunnel(HttpTunnelStream {
            stream: tls_stream,
            addr: addr.into(),
            auth: "Basic ".to_owned() + server.server_config().password(),
        }))
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed<A>(context: Arc<ServiceContext>, addr: A) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        AutoProxyClientStream::connect_bypassed_with_opts(context.clone(), addr, context.connect_opts_ref()).await
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed_with_opts<A>(
        context: Arc<ServiceContext>,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        // Connect directly.
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        let stream = TcpStream::connect_remote_with_opts(context.context_ref(), &addr, connect_opts).await?;
        Ok(AutoProxyClientStream::Bypassed(stream))
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        AutoProxyClientStream::connect_proxied_with_opts(context.clone(), server, addr, context.connect_opts_ref())
            .await
    }

    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied_with_opts<A>(
        context: Arc<ServiceContext>,
        server: &ServerIdent,
        addr: A,
        connect_opts: &ConnectOpts,
    ) -> io::Result<AutoProxyClientStream>
    where
        A: Into<Address>,
    {
        #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
        let mut addr = addr.into();
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = context.try_map_fake_address(&addr).await {
            addr = mapped_addr;
        }
        let flow_stat = context.flow_stat();
        let stream = match ProxyClientStream::connect_with_opts_map(
            context.context(),
            server.server_config(),
            addr,
            connect_opts,
            |stream| MonProxyStream::from_stream(stream, flow_stat),
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        };
        Ok(AutoProxyClientStream::Proxied(stream))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.get_ref().get_ref().local_addr(),
            AutoProxyClientStream::Bypassed(ref s) => s.local_addr(),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(ref s) => s.stream.get_ref().0.local_addr(),
        }
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.get_ref().get_ref().set_nodelay(nodelay),
            AutoProxyClientStream::Bypassed(ref s) => s.set_nodelay(nodelay),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStream::HttpTunnel(ref s) => s.stream.get_ref().0.set_nodelay(nodelay),
        }
    }
}
#[cfg(feature = "https-tunnel")]
async fn connect_tunnel(
    addr: Address,
    tls_stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    auth: &str,
) -> Result<(), io::Error> {
    let connect_string = match addr {
        Address::SocketAddress(sa) => {
            format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                sa.ip(),
                sa.port(),
                sa.ip(),
                auth
            )
        }
        Address::DomainNameAddress(domain, port) => {
            format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                domain, port, domain, auth
            )
        }
    };
    let mut addr_buf = BytesMut::with_capacity(connect_string.as_bytes().len());
    addr_buf.put_slice(connect_string.as_bytes());
    tls_stream.write_all(&addr_buf).await?;

    Ok(())
}
#[cfg(feature = "https-tunnel")]
async fn wait_response(tls_stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(4096); // 初始化BytesMut缓冲区
    let mut buf = [0; 4096]; // 临时缓冲区
    loop {
        // 从流中读取数据
        match tls_stream.read(&mut buf).await {
            Ok(n) => {
                if n != 0 {
                    // 将读取到的数据追加到动态缓冲区
                    buffer.put(&buf[0..n]);
                }

                // 尝试解析累积的数据
                let mut headers = [httparse::EMPTY_HEADER; 400];
                let mut response: Response<'_, '_> = Response::new(&mut headers);
                match response.parse(&buffer) {
                    Ok(Status::Complete(_)) => {
                        match response.code {
                            Some(200) => {
                                // 连接成功
                                return Ok(());
                            }
                            Some(code) => {
                                // 连接失败
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("failed to connect, response code: {}", code),
                                ));
                            }
                            None => {
                                // 无法解析响应码
                                return Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "failed to connect, response code not found",
                                ));
                            }
                        }
                    }
                    Ok(Status::Partial) => {
                        // 请求不完整，继续读取更多数据
                        println!("Received partial HTTP request, waiting for more data...");
                        // 不清空缓冲区，继续累积数据
                    }
                    Err(e) => {
                        // 解析错误
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                }
            }
            Err(e) => {
                // 读取数据时出错
                eprintln!("Failed to read from the stream: {:?}", e);
                return Err(e);
            }
        }
    }
}

impl AutoProxyIo for AutoProxyClientStream {
    fn is_proxied(&self) -> bool {
        !matches!(*self, AutoProxyClientStream::Bypassed(..))
    }
}

impl AsyncRead for AutoProxyClientStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_read(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_read(cx, buf),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AutoProxyClientStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write(cx, buf),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_flush(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_flush(cx),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_shutdown(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_shutdown(cx),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write_vectored(cx, bufs),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "https-tunnel")]
            AutoProxyClientStreamProj::HttpTunnel(s) => s.project().stream.poll_write_vectored(cx, bufs),
        }
    }
}

impl From<ProxyClientStream<MonProxyStream<TcpStream>>> for AutoProxyClientStream {
    fn from(s: ProxyClientStream<MonProxyStream<TcpStream>>) -> Self {
        AutoProxyClientStream::Proxied(s)
    }
}
