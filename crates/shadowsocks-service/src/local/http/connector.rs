//! HTTP Client connector

use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use futures::{future::BoxFuture, FutureExt};
use hyper::Uri;
use log::error;
use pin_project::pin_project;
use shadowsocks::{context::SharedContext, net::ConnectOpts};
use tower::Service;

use crate::{
    local::{loadbalancing::BasicServerIdent, net::AutoProxyClientStream},
    net::FlowStat,
};

use super::{http_stream::ProxyHttpStream, utils::host_addr};

#[derive(Clone)]
pub struct BypassConnector {
    context: SharedContext,
    connect_opts: Arc<ConnectOpts>,
}

impl BypassConnector {
    pub fn new(context: SharedContext, connect_opts: Arc<ConnectOpts>) -> BypassConnector {
        BypassConnector { context, connect_opts }
    }
}

impl Service<Uri> for BypassConnector {
    type Error = io::Error;
    type Future = BypassConnecting;
    type Response = ProxyHttpStream;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let context = self.context.clone();
        let connect_opts = self.connect_opts.clone();

        BypassConnecting {
            fut: async move {
                let is_https = dst.scheme_str() == Some("https");

                match host_addr(&dst) {
                    None => {
                        use std::io::Error;

                        error!("HTTP target URI must be a valid address, but found: {}", dst);

                        let err = Error::new(ErrorKind::Other, "URI must be a valid Address");
                        Err(err)
                    }
                    Some(addr) => {
                        let s = AutoProxyClientStream::connect_bypassed_with_opts(context, addr, &connect_opts).await?;

                        if is_https {
                            let host = dst.host().unwrap().trim_start_matches('[').trim_start_matches(']');
                            ProxyHttpStream::connect_https(s, host).await
                        } else {
                            Ok(ProxyHttpStream::connect_http(s))
                        }
                    }
                }
            }
            .boxed(),
        }
    }
}

#[pin_project]
pub struct BypassConnecting {
    #[pin]
    fut: BoxFuture<'static, io::Result<ProxyHttpStream>>,
}

impl Future for BypassConnecting {
    type Output = io::Result<ProxyHttpStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

#[derive(Clone)]
pub struct ProxyConnector {
    context: SharedContext,
    server: Arc<BasicServerIdent>,
    connect_opts: Arc<ConnectOpts>,
    flow_stat: Arc<FlowStat>,
}

impl ProxyConnector {
    pub fn new(
        context: SharedContext,
        server: Arc<BasicServerIdent>,
        connect_opts: Arc<ConnectOpts>,
        flow_stat: Arc<FlowStat>,
    ) -> ProxyConnector {
        ProxyConnector {
            context,
            server,
            connect_opts,
            flow_stat,
        }
    }
}

impl Service<Uri> for ProxyConnector {
    type Error = io::Error;
    type Future = ProxyConnecting;
    type Response = ProxyHttpStream;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let context = self.context.clone();
        let connect_opts = self.connect_opts.clone();
        let server = self.server.clone();
        let flow_stat = self.flow_stat.clone();

        ProxyConnecting {
            fut: async move {
                let is_https = dst.scheme_str() == Some("https");

                match host_addr(&dst) {
                    None => {
                        use std::io::Error;

                        error!("HTTP target URI must be a valid address, but found: {}", dst);

                        let err = Error::new(ErrorKind::Other, "URI must be a valid Address");
                        Err(err)
                    }
                    Some(addr) => {
                        let s = AutoProxyClientStream::connect_proxied_with_opts(
                            context,
                            server.as_ref(),
                            addr,
                            &connect_opts,
                            flow_stat,
                        )
                        .await?;

                        if is_https {
                            let host = dst.host().unwrap().trim_start_matches('[').trim_start_matches(']');
                            ProxyHttpStream::connect_https(s, host).await
                        } else {
                            Ok(ProxyHttpStream::connect_http(s))
                        }
                    }
                }
            }
            .boxed(),
        }
    }
}

#[pin_project]
pub struct ProxyConnecting {
    #[pin]
    fut: BoxFuture<'static, io::Result<ProxyHttpStream>>,
}

impl Future for ProxyConnecting {
    type Output = io::Result<ProxyHttpStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}
