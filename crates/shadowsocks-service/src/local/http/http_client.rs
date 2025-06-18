//! HTTP Client

use std::{
    borrow::Cow,
    collections::VecDeque,
    fmt::Debug,
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use http::{HeaderValue, Method as HttpMethod, Uri, Version as HttpVersion, header::InvalidHeaderValue};
use hyper::{
    Request, Response,
    body::{self, Body},
    client::conn::{http1, http2},
    http::uri::Scheme,
    rt::{Sleep, Timer},
};
use log::{error, trace};
use lru_time_cache::LruCache;
use pin_project::pin_project;
use shadowsocks::relay::Address;
use tokio::sync::Mutex;

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer, net::AutoProxyClientStream};

use super::{
    http_stream::ProxyHttpStream,
    tokio_rt::{TokioExecutor, TokioIo},
    utils::{check_keep_alive, connect_host, host_addr},
};

const CONNECTION_EXPIRE_DURATION: Duration = Duration::from_secs(20);

/// HTTPClient API request errors
#[derive(thiserror::Error, Debug)]
pub enum HttpClientError {
    /// Errors from hyper
    #[error("{0}")]
    Hyper(#[from] hyper::Error),
    /// std::io::Error
    #[error("{0}")]
    Io(#[from] io::Error),
    /// Errors from http
    #[error("{0}")]
    Http(#[from] http::Error),
    /// Errors from http header
    #[error("{0}")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
}

#[derive(Clone, Debug)]
pub struct TokioTimer;

impl Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep(duration),
        })
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: tokio::time::sleep_until(deadline.into()),
        })
    }

    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        if let Some(sleep) = sleep.as_mut().downcast_mut_pin::<TokioSleep>() {
            sleep.reset(new_deadline)
        }
    }
}

#[pin_project]
pub(crate) struct TokioSleep {
    #[pin]
    pub(crate) inner: tokio::time::Sleep,
}

impl Future for TokioSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

impl Sleep for TokioSleep {}

impl TokioSleep {
    pub fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.project().inner.as_mut().reset(deadline.into());
    }
}

/// HTTPClient, supporting HTTP/1.1 and H2, HTTPS.
pub struct HttpClient<B> {
    #[allow(clippy::type_complexity)]
    cache_conn: Arc<Mutex<LruCache<Address, VecDeque<(HttpConnection<B>, Instant)>>>>,
}

impl<B> Clone for HttpClient<B> {
    fn clone(&self) -> Self {
        Self {
            cache_conn: self.cache_conn.clone(),
        }
    }
}

impl<B> Default for HttpClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<B> HttpClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    /// Create a new HttpClient
    pub fn new() -> Self {
        Self {
            cache_conn: Arc::new(Mutex::new(LruCache::with_expiry_duration(CONNECTION_EXPIRE_DURATION))),
        }
    }

    /// Make HTTP requests
    #[inline]
    pub async fn send_request(
        &self,
        context: Arc<ServiceContext>,
        req: Request<B>,
        balancer: Option<&PingBalancer>,
    ) -> Result<Response<body::Incoming>, HttpClientError> {
        let host = match host_addr(req.uri()) {
            Some(h) => h,
            None => panic!("URI missing host: {}", req.uri()),
        };

        // Set Host header if it was missing in the Request
        let (mut req_parts, req_body) = req.into_parts();
        if let Some(authority) = req_parts.uri.authority() {
            let headers = &mut req_parts.headers;
            if !headers.contains_key("Host") {
                let uri = &req_parts.uri;
                let host_value = if (uri.scheme_str() == Some("http")
                    && matches!(authority.port_u16(), None | Some(80)))
                    || (uri.scheme_str() == Some("https") && matches!(authority.port_u16(), None | Some(443)))
                {
                    HeaderValue::from_str(authority.host())?
                } else {
                    HeaderValue::from_str(authority.as_str())?
                };

                headers.insert("Host", host_value);
            }
        }
        let req = Request::from_parts(req_parts, req_body);

        // 1. Check if there is an available client
        //
        // FIXME: If the cached connection is closed unexpectedly, this request will fail immediately.
        if let Some(c) = self.get_cached_connection(&host).await {
            trace!("HTTP client for host: {} taken from cache", host);
            return self.send_request_conn(host, c, req).await;
        }

        // 2. If no. Make a new connection
        let scheme = match req.uri().scheme() {
            Some(s) => s,
            None => &Scheme::HTTP,
        };

        let domain = match host {
            Address::DomainNameAddress(ref domain, _) => Cow::Borrowed(domain.as_str()),
            Address::SocketAddress(ref saddr) => Cow::Owned(saddr.ip().to_string()),
        };

        let c = match HttpConnection::connect(context.clone(), scheme, host.clone(), &domain, balancer).await {
            Ok(c) => c,
            Err(err) => {
                error!("failed to connect to host: {}, error: {}", host, err);
                return Err(err.into());
            }
        };

        self.send_request_conn(host, c, req).await
    }

    async fn get_cached_connection(&self, host: &Address) -> Option<HttpConnection<B>> {
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
        mut c: HttpConnection<B>,
        req: Request<B>,
    ) -> Result<Response<body::Incoming>, HttpClientError> {
        trace!("HTTP making request to host: {}, request: {:?}", host, req);
        let response = c.send_request(req).await?;
        trace!("HTTP received response from host: {}, response: {:?}", host, response);

        // Check keep-alive
        if check_keep_alive(response.version(), response.headers(), false) {
            trace!(
                "HTTP connection keep-alive for host: {}, response: {:?}",
                host, response
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

enum HttpConnection<B> {
    Http1(http1::SendRequest<B>),
    Http2(http2::SendRequest<B>),
}

impl<B> HttpConnection<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    async fn connect(
        context: Arc<ServiceContext>,
        scheme: &Scheme,
        host: Address,
        domain: &str,
        balancer: Option<&PingBalancer>,
    ) -> io::Result<Self> {
        if *scheme != Scheme::HTTP && *scheme != Scheme::HTTPS {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid scheme"));
        }

        let (stream, _) = connect_host(context, &host, balancer).await?;

        if *scheme == Scheme::HTTP {
            Self::connect_http_http1(scheme, host, stream).await
        } else if *scheme == Scheme::HTTPS {
            Self::connect_https(scheme, host, domain, stream).await
        } else {
            unreachable!()
        }
    }

    async fn connect_http_http1(scheme: &Scheme, host: Address, stream: AutoProxyClientStream) -> io::Result<Self> {
        trace!(
            "HTTP making new HTTP/1.1 connection to host: {}, scheme: {}",
            host, scheme
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
            Err(err) => return Err(io::Error::other(err)),
        };

        tokio::spawn(async move {
            if let Err(err) = connection.await {
                error!("HTTP/1.x connection to host: {} aborted with error: {}", host, err);
            }
        });

        Ok(Self::Http1(send_request))
    }

    async fn connect_https(
        scheme: &Scheme,
        host: Address,
        domain: &str,
        stream: AutoProxyClientStream,
    ) -> io::Result<Self> {
        trace!("HTTP making new TLS connection to host: {}, scheme: {}", host, scheme);

        // TLS handshake, check alpn for h2 support.
        let stream = ProxyHttpStream::connect_https(stream, domain).await?;

        if stream.negotiated_http2() {
            // H2 connection
            let (send_request, connection) = match http2::Builder::new(TokioExecutor)
                .timer(TokioTimer)
                .keep_alive_interval(Duration::from_secs(15))
                .handshake(TokioIo::new(stream))
                .await
            {
                Ok(s) => s,
                Err(err) => return Err(io::Error::other(err)),
            };

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    error!("HTTP/2 TLS connection to host: {} aborted with error: {}", host, err);
                }
            });

            Ok(Self::Http2(send_request))
        } else {
            // HTTP/1.x TLS
            let (send_request, connection) = match http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(stream))
                .await
            {
                Ok(s) => s,
                Err(err) => return Err(io::Error::other(err)),
            };

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    error!("HTTP/1.x TLS connection to host: {} aborted with error: {}", host, err);
                }
            });

            Ok(Self::Http1(send_request))
        }
    }

    #[inline]
    pub async fn send_request(&mut self, mut req: Request<B>) -> Result<Response<body::Incoming>, HttpClientError> {
        match self {
            Self::Http1(r) => {
                if !matches!(
                    req.version(),
                    HttpVersion::HTTP_09 | HttpVersion::HTTP_10 | HttpVersion::HTTP_11
                ) {
                    trace!(
                        "HTTP client changed Request.version to HTTP/1.1 from {:?}",
                        req.version()
                    );

                    *req.version_mut() = HttpVersion::HTTP_11;
                }

                // Remove Scheme, Host part from URI
                if req.method() != HttpMethod::CONNECT
                    && (req.uri().scheme().is_some() || req.uri().authority().is_some())
                {
                    let mut builder = Uri::builder();
                    match req.uri().path_and_query() {
                        Some(path_and_query) => {
                            builder = builder.path_and_query(path_and_query.as_str());
                        }
                        _ => {
                            builder = builder.path_and_query("/");
                        }
                    }
                    *(req.uri_mut()) = builder.build()?;
                }

                r.send_request(req).await.map_err(Into::into)
            }
            Self::Http2(r) => {
                if !matches!(req.version(), HttpVersion::HTTP_2) {
                    trace!("HTTP client changed Request.version to HTTP/2 from {:?}", req.version());

                    *req.version_mut() = HttpVersion::HTTP_2;
                }

                r.send_request(req).await.map_err(Into::into)
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            Self::Http1(r) => r.is_closed(),
            Self::Http2(r) => r.is_closed(),
        }
    }
}
