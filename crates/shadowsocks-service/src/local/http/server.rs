//! Shadowsocks Local HTTP proxy server
//!
//! https://www.ietf.org/rfc/rfc2068.txt

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use hyper::{body, server::conn::http1, service};
use log::{error, info, trace};
use shadowsocks::{config::ServerAddr, net::TcpListener};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time,
};

use crate::local::{
    context::ServiceContext, loadbalancing::PingBalancer, net::tcp::listener::create_standard_tcp_listener,
};

use super::{http_client::HttpClient, http_service::HttpService, tokio_rt::TokioIo};

/// HTTP Local server builder
pub struct HttpBuilder {
    context: Arc<ServiceContext>,
    client_config: ServerAddr,
    balancer: PingBalancer,
    #[cfg(target_os = "macos")]
    launchd_tcp_socket_name: Option<String>,
}

impl HttpBuilder {
    /// Create a new HTTP Local server builder
    pub fn new(client_config: ServerAddr, balancer: PingBalancer) -> Self {
        let context = ServiceContext::new();
        Self::with_context(Arc::new(context), client_config, balancer)
    }

    /// Create with an existed context
    pub fn with_context(context: Arc<ServiceContext>, client_config: ServerAddr, balancer: PingBalancer) -> Self {
        Self {
            context,
            client_config,
            balancer,
            #[cfg(target_os = "macos")]
            launchd_tcp_socket_name: None,
        }
    }

    #[cfg(target_os = "macos")]
    pub fn set_launchd_tcp_socket_name(&mut self, n: String) {
        self.launchd_tcp_socket_name = Some(n);
    }

    /// Build HTTP server instance
    pub async fn build(self) -> io::Result<Http> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                let listener = match self.launchd_tcp_socket_name {
                    Some(launchd_socket_name) => {
                        use tokio::net::TcpListener as TokioTcpListener;
                        use crate::net::launch_activate_socket::get_launch_activate_tcp_listener;

                        let std_listener = get_launch_activate_tcp_listener(&launchd_socket_name, true)?;
                        let tokio_listener = TokioTcpListener::from_std(std_listener)?;
                        TcpListener::from_listener(tokio_listener, self.context.accept_opts())?
                    } _ => {
                        create_standard_tcp_listener(&self.context, &self.client_config).await?
                    }
                };
            } else {
                let listener = create_standard_tcp_listener(&self.context, &self.client_config).await?;
            }
        }

        // let proxy_client_cache = Arc::new(ProxyClientCache::new(self.context.clone()));

        Ok(Http {
            context: self.context,
            listener,
            balancer: self.balancer,
        })
    }
}

/// HTTP Local server
pub struct Http {
    context: Arc<ServiceContext>,
    listener: TcpListener,
    balancer: PingBalancer,
}

impl Http {
    /// Server's local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run server
    pub async fn run(self) -> io::Result<()> {
        // https://www.ietf.org/rfc/rfc2068.txt
        // HTTP Proxy is based on HTTP/1.1

        info!(
            "shadowsocks HTTP listening on {}",
            self.listener.local_addr().expect("http local_addr")
        );

        let handler = HttpConnectionHandler::new(self.context, self.balancer);

        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("failed to accept HTTP clients, err: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            trace!("HTTP accepted client from {}", peer_addr);
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Err(err) = handler.serve_connection(stream, peer_addr).await {
                    error!("HTTP connection {} handler failed with error: {}", peer_addr, err);
                }
            });
        }
    }
}

/// HTTP Proxy handler for `accept()`ed HTTP clients
///
/// It should be created once and then `clone()` for every individual TCP connections
#[derive(Clone)]
pub struct HttpConnectionHandler {
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    http_client: HttpClient<body::Incoming>,
}

impl HttpConnectionHandler {
    /// Create a new Handler
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer) -> Self {
        Self {
            context,
            balancer,
            http_client: HttpClient::new(),
        }
    }

    /// Handle a TCP HTTP connection
    pub async fn serve_connection<S>(self, stream: S, peer_addr: SocketAddr) -> hyper::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Self {
            context,
            balancer,
            http_client,
        } = self;

        let io = TokioIo::new(stream);

        // NOTE: Some stupid clients requires HTTP header keys to be case-sensitive.
        // For example: Nintendo Switch
        http1::Builder::new()
            .keep_alive(true)
            .title_case_headers(true)
            .preserve_header_case(true)
            .serve_connection(
                io,
                service::service_fn(move |req| {
                    HttpService::new(context.clone(), peer_addr, http_client.clone(), balancer.clone())
                        .serve_connection(req)
                }),
            )
            .with_upgrades()
            .await
    }
}
