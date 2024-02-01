//! HTTP Client

use std::{
    collections::VecDeque,
    io::{self, ErrorKind},
    sync::Arc,
    time::{Duration, Instant},
};

use hyper::{
    body,
    client::conn::{http1, http2},
    http::uri::Scheme,
    Request,
    Response,
};
use log::{error, trace};
use lru_time_cache::LruCache;
use shadowsocks::relay::Address;
use tokio::sync::Mutex;

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer, net::AutoProxyClientStream};

use super::{
    http_stream::ProxyHttpStream,
    tokio_rt::{TokioExecutor, TokioIo},
    utils::{check_keep_alive, connect_host, host_addr},
};

const CONNECTION_EXPIRE_DURATION: Duration = Duration::from_secs(20);

#[derive(thiserror::Error, Debug)]
pub enum HttpClientError {
    #[error("{0}")]
    Hyper(#[from] hyper::Error),
    #[error("{0}")]
    Io(#[from] io::Error),
}

#[derive(Clone)]
pub struct HttpClient {
    #[allow(clippy::type_complexity)]
    cache_conn: Arc<Mutex<LruCache<Address, VecDeque<(HttpConnection, Instant)>>>>,
}

impl HttpClient {
    pub fn new() -> HttpClient {
        HttpClient {
            cache_conn: Arc::new(Mutex::new(LruCache::with_expiry_duration(CONNECTION_EXPIRE_DURATION))),
        }
    }

    #[inline]
    pub async fn send_request(
        &self,
        context: Arc<ServiceContext>,
        req: Request<body::Incoming>,
        balancer: &PingBalancer,
    ) -> Result<Response<body::Incoming>, HttpClientError> {
        let host = match host_addr(req.uri()) {
            Some(h) => h,
            None => panic!("URI missing host: {}", req.uri()),
        };

        // 1. Check if there is an available client
        //
        // FIXME: If the cached connection is closed unexpectly, this request will fail immediately.
        if let Some(c) = self.get_cached_connection(&host).await {
            trace!("HTTP client for host: {} taken from cache", host);
            match self.send_request_conn(host, c, req).await {
                Ok(o) => return Ok(o),
                Err(err) => return Err(err.into()),
            }
        }

        // 2. If no. Make a new connection
        let scheme = match req.uri().scheme() {
            Some(s) => s,
            None => &Scheme::HTTP,
        };

        let domain = req
            .uri()
            .host()
            .unwrap()
            .trim_start_matches('[')
            .trim_start_matches(']');
        let c = match HttpConnection::connect(context.clone(), scheme, host.clone(), domain, balancer).await {
            Ok(c) => c,
            Err(err) => {
                error!("failed to connect to host: {}, error: {}", host, err);
                return Err(err.into());
            }
        };

        self.send_request_conn(host, c, req).await.map_err(Into::into)
    }

    async fn get_cached_connection(&self, host: &Address) -> Option<HttpConnection> {
        if let Some(q) = self.cache_conn.lock().await.get_mut(host) {
            while let Some((c, inst)) = q.pop_front() {
                let now = Instant::now();
                if now - inst >= CONNECTION_EXPIRE_DURATION {
                    continue;
                }
                if c.is_closed() {
                    continue;
                }
                return Some(c);
            }
        }
        None
    }

    async fn send_request_conn(
        &self,
        host: Address,
        mut c: HttpConnection,
        req: Request<body::Incoming>,
    ) -> hyper::Result<Response<body::Incoming>> {
        trace!("HTTP making request to host: {}, request: {:?}", host, req);
        let response = c.send_request(req).await?;
        trace!("HTTP received response from host: {}, response: {:?}", host, response);

        // Check keep-alive
        if check_keep_alive(response.version(), response.headers(), false) {
            trace!(
                "HTTP connection keep-alive for host: {}, response: {:?}",
                host,
                response
            );
            self.cache_conn
                .lock()
                .await
                .entry(host)
                .or_insert_with(VecDeque::new)
                .push_back((c, Instant::now()));
        }

        Ok(response)
    }
}

enum HttpConnection {
    Http1(http1::SendRequest<body::Incoming>),
    Http2(http2::SendRequest<body::Incoming>),
}

impl HttpConnection {
    async fn connect(
        context: Arc<ServiceContext>,
        scheme: &Scheme,
        host: Address,
        domain: &str,
        balancer: &PingBalancer,
    ) -> io::Result<HttpConnection> {
        if *scheme != Scheme::HTTP && *scheme != Scheme::HTTPS {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid scheme"));
        }

        let (stream, _) = connect_host(context, &host, balancer).await?;

        if *scheme == Scheme::HTTP {
            HttpConnection::connect_http_http1(scheme, host, stream).await
        } else if *scheme == Scheme::HTTPS {
            HttpConnection::connect_https(scheme, host, domain, stream).await
        } else {
            unreachable!()
        }
    }

    async fn connect_http_http1(
        scheme: &Scheme,
        host: Address,
        stream: AutoProxyClientStream,
    ) -> io::Result<HttpConnection> {
        trace!(
            "HTTP making new HTTP/1.1 connection to host: {}, scheme: {}",
            host,
            scheme
        );

        let stream = ProxyHttpStream::connect_http(stream);

        // HTTP/1.x
        let (send_request, connection) = match http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(TokioIo::new(stream))
            .await
        {
            Ok(s) => s,
            Err(err) => return Err(io::Error::new(ErrorKind::Other, err)),
        };

        tokio::spawn(async move {
            if let Err(err) = connection.await {
                error!("HTTP/1.x connection to host: {} aborted with error: {}", host, err);
            }
        });

        Ok(HttpConnection::Http1(send_request))
    }

    async fn connect_https(
        scheme: &Scheme,
        host: Address,
        domain: &str,
        stream: AutoProxyClientStream,
    ) -> io::Result<HttpConnection> {
        trace!("HTTP making new TLS connection to host: {}, scheme: {}", host, scheme);

        // TLS handshake, check alpn for h2 support.
        let stream = ProxyHttpStream::connect_https(stream, domain).await?;

        if stream.negotiated_http2() {
            // H2 connnection
            let (send_request, connection) = match http2::Builder::new(TokioExecutor)
                .keep_alive_interval(Duration::from_secs(15))
                .handshake(TokioIo::new(stream))
                .await
            {
                Ok(s) => s,
                Err(err) => return Err(io::Error::new(ErrorKind::Other, err)),
            };

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    error!("HTTP/2 TLS connection to host: {} aborted with error: {}", host, err);
                }
            });

            Ok(HttpConnection::Http2(send_request))
        } else {
            // HTTP/1.x TLS
            let (send_request, connection) = match http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(stream))
                .await
            {
                Ok(s) => s,
                Err(err) => return Err(io::Error::new(ErrorKind::Other, err)),
            };

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    error!("HTTP/1.x TLS connection to host: {} aborted with error: {}", host, err);
                }
            });

            Ok(HttpConnection::Http1(send_request))
        }
    }

    #[inline]
    pub async fn send_request(&mut self, req: Request<body::Incoming>) -> hyper::Result<Response<body::Incoming>> {
        match self {
            HttpConnection::Http1(r) => r.send_request(req).await,
            HttpConnection::Http2(r) => r.send_request(req).await,
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            HttpConnection::Http1(r) => r.is_closed(),
            HttpConnection::Http2(r) => r.is_closed(),
        }
    }
}
