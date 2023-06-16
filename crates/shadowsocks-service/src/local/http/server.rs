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
use shadowsocks::{config::ServerAddr, lookup_then, net::TcpListener};

use crate::local::{
    context::ServiceContext,
    http::connector::Connector,
    loadbalancing::PingBalancer,
    LOCAL_DEFAULT_KEEPALIVE_TIMEOUT,
};

use super::{client_cache::ProxyClientCache, dispatcher::HttpDispatcher};

/// HTTP Local server builder
pub struct HttpBuilder {
    context: Arc<ServiceContext>,
    client_config: ServerAddr,
    balancer: PingBalancer,
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
        }
    }

    /// Build HTTP server instance
    pub async fn build(self) -> io::Result<Http> {
        let listener = match self.client_config {
            ServerAddr::SocketAddr(sa) => TcpListener::bind_with_opts(&sa, self.context.accept_opts().clone()).await,
            ServerAddr::DomainName(ref dname, port) => lookup_then!(self.context.context_ref(), dname, port, |addr| {
                TcpListener::bind_with_opts(&addr, self.context.accept_opts().clone()).await
            })
            .map(|(_, b)| b),
        }?;

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
