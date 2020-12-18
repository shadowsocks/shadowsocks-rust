//! Shadowsocks Local HTTP(S) Server

use std::{
    convert::Infallible,
    io::{self, ErrorKind},
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
use shadowsocks::{
    config::{ServerAddr, ServerConfig},
    lookup_then,
};

use crate::{
    config::ClientConfig,
    local::{
        context::ServiceContext,
        loadbalancing::{PingBalancerBuilder, ServerType as BalancerServerType},
    },
};

use super::{connector::BypassConnector, dispatcher::HttpDispatcher, server_ident::HttpServerIdent};

/// HTTP Local server
pub struct Http {
    context: Arc<ServiceContext>,
}

impl Http {
    /// Create a new HTTP Local server
    pub fn new() -> Http {
        let context = ServiceContext::new();
        Http::with_context(Arc::new(context))
    }

    /// Create with an existed context
    pub fn with_context(context: Arc<ServiceContext>) -> Http {
        Http { context }
    }

    /// Run server
    pub async fn run(self, client_config: &ClientConfig, servers: &[ServerConfig]) -> io::Result<()> {
        let mut balancer_builder = PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Tcp);

        for server in servers {
            let server_ident = HttpServerIdent::new(self.context.clone(), server.clone());
            balancer_builder.add_server(server_ident);
        }

        let (balancer, checker) = balancer_builder.build();
        tokio::spawn(checker);

        let bypass_client = Client::builder().build::<_, Body>(BypassConnector::new(self.context.clone()));

        let context = self.context.clone();
        let make_service = make_service_fn(|socket: &AddrStream| {
            let client_addr = socket.remote_addr();
            let balancer = balancer.clone();
            let bypass_client = bypass_client.clone();
            let context = context.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let server = balancer.best_server();
                    HttpDispatcher::new(context.clone(), req, server, client_addr, bypass_client.clone()).dispatch()
                }))
            }
        });

        let bind_result = match *client_config {
            ServerAddr::SocketAddr(sa) => Server::try_bind(&sa),
            ServerAddr::DomainName(ref dname, port) => lookup_then!(self.context.context_ref(), dname, port, |addr| {
                Server::try_bind(&addr)
            })
            .map(|(_, b)| b),
        };

        // HTTP Proxy protocol only defined in HTTP 1.x
        let server = match bind_result {
            Ok(builder) => builder
                .http1_only(true)
                .tcp_sleep_on_accept_errors(true)
                .serve(make_service),
            Err(err) => {
                error!("hyper server bind error: {}", err);
                let err = io::Error::new(ErrorKind::InvalidInput, err);
                return Err(err);
            }
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
