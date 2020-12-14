//! Shadowsocks Local HTTP(S) Server

use std::{
    convert::Infallible,
    io::{self, ErrorKind},
    path::PathBuf,
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
    config::{ServerAddr, ServerConfig, ServerType},
    context::{Context, SharedContext},
    dns_resolver::DnsResolver,
    lookup_then,
    net::ConnectOpts,
    plugin::{Plugin, PluginMode},
};

use crate::{
    config::ClientConfig,
    local::{
        acl::AccessControl,
        loadbalancing::{PingBalancerBuilder, ServerType as BalancerServerType},
    },
    net::FlowStat,
};

use super::{connector::BypassConnector, dispatcher::HttpDispatcher, server_ident::HttpServerIdent};

pub struct Http {
    context: SharedContext,
    flow_stat: Arc<FlowStat>,
    client_config: ClientConfig,
    servers: Vec<ServerConfig>,
    connect_opts: Arc<ConnectOpts>,
    acl: Option<Arc<AccessControl>>,
    #[cfg(feature = "local-http-native-tls")]
    tls_identity_path: Option<PathBuf>,
    #[cfg(feature = "local-http-native-tls")]
    tls_identity_password: Option<String>,
    #[cfg(feature = "local-http-rustls")]
    tls_identity_certificate_path: Option<PathBuf>,
    #[cfg(feature = "local-http-rustls")]
    tls_identity_private_key_path: Option<PathBuf>,
}

impl Http {
    pub fn new(client_config: ClientConfig, servers: Vec<ServerConfig>) -> Http {
        let context = Context::new_shared(ServerType::Server);
        Http::with_context(context, client_config, servers)
    }

    fn with_context(context: SharedContext, client_config: ClientConfig, servers: Vec<ServerConfig>) -> Http {
        Http {
            context,
            flow_stat: Arc::new(FlowStat::new()),
            client_config,
            servers,
            connect_opts: Arc::new(ConnectOpts::default()),
            acl: None,
            #[cfg(feature = "local-http-native-tls")]
            tls_identity_path: None,
            #[cfg(feature = "local-http-native-tls")]
            tls_identity_password: None,
            #[cfg(feature = "local-http-rustls")]
            tls_identity_certificate_path: None,
            #[cfg(feature = "local-http-rustls")]
            tls_identity_private_key_path: None,
        }
    }

    pub fn flow_stat(&self) -> &Arc<FlowStat> {
        &self.flow_stat
    }

    pub fn set_connect_opts(&mut self, opts: Arc<ConnectOpts>) {
        self.connect_opts = opts;
    }

    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        let context = Arc::get_mut(&mut self.context).expect("cannot set DNS resolver on a shared context");
        context.set_dns_resolver(resolver)
    }

    pub fn set_acl(&mut self, acl: Arc<AccessControl>) {
        self.acl = Some(acl);
    }

    #[cfg(feature = "local-http-native-tls")]
    fn is_https(&self) -> bool {
        self.tls_identity_path.is_some() && self.tls_identity_password.is_some()
    }

    #[cfg(feature = "local-http-rustls")]
    fn is_https(&self) -> bool {
        self.tls_identity_certificate_path.is_some() && self.tls_identity_private_key_path.is_some()
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
        let mut balancer_builder =
            PingBalancerBuilder::new(self.context.clone(), BalancerServerType::Tcp, self.connect_opts.clone());

        for server in self.servers {
            let server_ident = HttpServerIdent::new(
                self.context.clone(),
                server,
                self.connect_opts.clone(),
                self.flow_stat.clone(),
            );
            balancer_builder.add_server(server_ident);
        }

        let (balancer, checker) = balancer_builder.build();
        tokio::spawn(checker);

        let bypass_client =
            Client::builder().build::<_, Body>(BypassConnector::new(self.context.clone(), self.connect_opts.clone()));

        let context = self.context.clone();
        let connect_opts = self.connect_opts.clone();
        let flow_stat = self.flow_stat.clone();
        let acl = self.acl.clone();
        let make_service = make_service_fn(|socket: &AddrStream| {
            let client_addr = socket.remote_addr();
            let balancer = balancer.clone();
            let bypass_client = bypass_client.clone();
            let context = context.clone();
            let connect_opts = connect_opts.clone();
            let flow_stat = flow_stat.clone();
            let acl = acl.clone();

            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let server = balancer.best_server();
                    HttpDispatcher::new(
                        context.clone(),
                        req,
                        server,
                        client_addr,
                        bypass_client.clone(),
                        connect_opts.clone(),
                        flow_stat.clone(),
                        acl.clone(),
                    )
                    .dispatch()
                }))
            }
        });

        let bind_result = match self.client_config {
            ServerAddr::SocketAddr(sa) => Server::try_bind(&sa),
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(&self.context, dname, port, |addr| { Server::try_bind(&addr) }).map(|(_, b)| b)
            }
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
