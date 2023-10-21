//! Shadowsocks Local HTTP(S) Server

use std::{
    convert::Infallible,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body,
    Client,
    Request,
    Server,
};
use log::{error, info};
use shadowsocks::{config::ServerAddr, net::TcpListener};

use crate::{
    local::{
        context::ServiceContext,
        http::connector::Connector,
        loadbalancing::PingBalancer,
        LOCAL_DEFAULT_KEEPALIVE_TIMEOUT,
    },
    net::listener::create_standard_tcp_listener,
};

use super::{client_cache::ProxyClientCache, dispatcher::HttpDispatcher};

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
    pub fn new(client_config: ServerAddr, balancer: PingBalancer) -> HttpBuilder {
        let context = ServiceContext::new();
        HttpBuilder::with_context(Arc::new(context), client_config, balancer)
    }

    /// Create with an existed context
    pub fn with_context(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        balancer: PingBalancer,
    ) -> HttpBuilder {
        HttpBuilder {
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
                let listener = if let Some(launchd_socket_name) = self.launchd_tcp_socket_name {
                    use tokio::net::TcpListener as TokioTcpListener;
                    use crate::net::launch_activate_socket::get_launch_activate_tcp_listener;

                    match get_launch_activate_tcp_listener(&launchd_socket_name)? {
                        Some(std_listener) => {
                            let tokio_listener = TokioTcpListener::from_std(std_listener)?;
                            TcpListener::from_listener(tokio_listener, self.context.accept_opts())?
                        }
                        None => create_standard_tcp_listener(&self.context, &self.client_config).await?
                    }
                } else {
                    create_standard_tcp_listener(&self.context, &self.client_config).await?
                };
            } else {
                let listener = create_standard_tcp_listener(&self.context, &self.client_config).await?;
            }
        }

        let proxy_client_cache = Arc::new(ProxyClientCache::new(self.context.clone()));

        Ok(Http {
            context: self.context,
            proxy_client_cache,
            listener,
            balancer: self.balancer,
        })
    }
}

/// HTTP Local server
pub struct Http {
    context: Arc<ServiceContext>,
    proxy_client_cache: Arc<ProxyClientCache>,
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
        let bypass_client = Client::builder()
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .build::<_, Body>(Connector::new(self.context.clone(), None));

        let context = self.context.clone();
        let proxy_client_cache = self.proxy_client_cache.clone();
        let balancer = self.balancer;
        let make_service = make_service_fn(|socket: &AddrStream| {
            let client_addr = socket.remote_addr();
            let balancer = balancer.clone();
            let bypass_client = bypass_client.clone();
            let context = context.clone();
            let proxy_client_cache = proxy_client_cache.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    HttpDispatcher::new(
                        context.clone(),
                        req,
                        balancer.clone(),
                        client_addr,
                        bypass_client.clone(),
                        proxy_client_cache.clone(),
                    )
                    .dispatch()
                }))
            }
        });

        let server = {
            let listener = self.listener.into_inner().into_std()?;
            let builder = match Server::from_tcp(listener) {
                Ok(builder) => builder,
                Err(err) => {
                    error!("hyper server from std::net::TcpListener error: {}", err);
                    let err = io::Error::new(ErrorKind::InvalidInput, err);
                    return Err(err);
                }
            };

            builder
                    .http1_only(true) // HTTP Proxy protocol only defined in HTTP 1.x
                    .http1_preserve_header_case(true)
                    .http1_title_case_headers(true)
                    .tcp_sleep_on_accept_errors(true)
                    .tcp_keepalive(
                        self.context
                            .accept_opts()
                            .tcp
                            .keepalive
                            .or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT)),
                    )
                    .tcp_nodelay(self.context.accept_opts().tcp.nodelay)
                    .serve(make_service)
        };

        info!("shadowsocks HTTP listening on {}", server.local_addr());

        if let Err(err) = server.await {
            use std::io::Error;

            error!("hyper server exited with error: {}", err);
            return Err(Error::new(ErrorKind::Other, err));
        }

        Ok(())
    }
}
