//! Shadowsocks Local HTTP(S) Server

use std::{
    convert::Infallible,
    io::{self, ErrorKind},
    sync::Arc,
};

use futures::future::{self, FutureExt};
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
    plugin::{Plugin, PluginMode},
};

use crate::{
    config::ClientConfig,
    local::{
        context::ServiceContext,
        loadbalancing::{PingBalancerBuilder, ServerType as BalancerServerType},
    },
};

use super::{connector::BypassConnector, dispatcher::HttpDispatcher, server_ident::HttpServerIdent};

pub struct Http {
    context: Arc<ServiceContext>,
    client_config: ClientConfig,
    servers: Vec<ServerConfig>,
}

impl Http {
    pub fn new(client_config: ClientConfig, servers: Vec<ServerConfig>) -> Http {
        let context = ServiceContext::new();
        Http::with_context(Arc::new(context), client_config, servers)
    }

    pub fn with_context(context: Arc<ServiceContext>, client_config: ClientConfig, servers: Vec<ServerConfig>) -> Http {
        Http {
            context,
            client_config,
            servers,
        }
    }

    pub async fn run(mut self) -> io::Result<()> {
        let mut vfut = Vec::new();

        for server in &mut self.servers {
            if let Some(c) = server.plugin() {
                let plugin = Plugin::start(c, server.addr(), PluginMode::Client)?;
                server.set_plugin_addr(plugin.local_addr().into());
                vfut.push(async move { plugin.join().map(|r| r.map(|_| ())).await }.boxed());
            }
        }

        vfut.push(self.run_http_server().boxed());

        let _ = future::select_all(vfut).await;

        let err = io::Error::new(ErrorKind::Other, "http server exited unexpectly");
        Err(err)
    }

    async fn run_http_server(self) -> io::Result<()> {
        let mut balancer_builder = PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Tcp);

        for server in self.servers {
            let server_ident = HttpServerIdent::new(self.context.clone(), server);
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

        let bind_result = match self.client_config {
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
