//! Load Balancer chooses server by statistic latency data collected from active probing

use std::{
    fmt::{self, Debug},
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use byte_string::ByteStr;
use futures::future::{self, AbortHandle};
use log::{debug, info, trace};
use shadowsocks::relay::{
    socks5::Address,
    tcprelay::proxy_stream::ProxyClientStream,
    udprelay::{proxy_socket::ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    time,
};

use crate::local::context::ServiceContext;

use super::{
    server_data::ServerIdent,
    server_stat::{Score, DEFAULT_CHECK_INTERVAL_SEC, DEFAULT_CHECK_TIMEOUT_SEC},
};

/// Remote Server Type
#[derive(Debug, Clone, Copy)]
pub enum ServerType {
    Tcp,
    Udp,
}

impl fmt::Display for ServerType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ServerType::Tcp => f.write_str("TCP"),
            ServerType::Udp => f.write_str("UDP"),
        }
    }
}

/// Build a `PingBalancer`
pub struct PingBalancerBuilder<C>
where
    C: ServerIdent,
{
    servers: Vec<Arc<C>>,
    context: Arc<ServiceContext>,
    server_type: ServerType,
}

impl<C> PingBalancerBuilder<C>
where
    C: ServerIdent,
{
    pub fn new(context: Arc<ServiceContext>, server_type: ServerType) -> PingBalancerBuilder<C> {
        PingBalancerBuilder {
            servers: Vec::new(),
            context,
            server_type,
        }
    }

    pub fn add_server(&mut self, server: C) {
        self.servers.push(Arc::new(server));
    }

    pub fn build(self) -> (PingBalancer<C>, impl Future<Output = ()>) {
        assert!(!self.servers.is_empty(), "build PingBalancer without any servers");

        let balancer = PingBalancerInner {
            servers: self.servers,
            best_idx: AtomicUsize::new(0),
            context: self.context,
            server_type: self.server_type,
        };

        let shared = Arc::new(balancer);
        let inner = shared.clone();

        let (checker, abortable) = future::abortable(async move { shared.checker_task().await });
        let checker = async move {
            let _ = checker.await;
        };

        let balancer = PingBalancer {
            inner,
            abortable: Arc::new(abortable),
        };
        (balancer, checker)
    }
}

struct PingBalancerInner<C> {
    servers: Vec<Arc<C>>,
    best_idx: AtomicUsize,
    context: Arc<ServiceContext>,
    server_type: ServerType,
}

impl<C> PingBalancerInner<C> {
    fn best_server(&self) -> Arc<C> {
        self.servers[self.best_idx.load(Ordering::Relaxed)].clone()
    }
}

impl<C> PingBalancerInner<C>
where
    C: ServerIdent,
{
    async fn checker_task(self: Arc<Self>) {
        assert!(!self.servers.is_empty(), "check PingBalancer without any servers");

        if self.servers.len() == 1 {
            self.checker_task_dummy().await
        } else {
            self.checker_task_real().await
        }
    }

    /// Dummy task that will do nothing if there only have one server in the balancer
    async fn checker_task_dummy(self: Arc<Self>) {
        future::pending().await
    }

    /// Check each servers' score and update the best server's index
    async fn checker_task_real(self: Arc<Self>) {
        loop {
            let mut vfut = Vec::with_capacity(self.servers.len());

            for server in self.servers.iter() {
                let checker = PingChecker {
                    server: server.clone(),
                    server_type: self.server_type,
                    context: self.context.clone(),
                };
                vfut.push(checker.check_update_score());
            }

            future::join_all(vfut).await;

            let old_best_idx = self.best_idx.load(Ordering::Acquire);

            let mut best_idx = 0;
            let mut best_score = u64::MAX;
            for (idx, server) in self.servers.iter().enumerate() {
                let score = server.server_score().score();
                if score < best_score {
                    best_idx = idx;
                    best_score = score;
                }
            }
            self.best_idx.store(best_idx, Ordering::Release);

            if best_idx != old_best_idx {
                info!(
                    "switched best {} server from {} to {}",
                    self.server_type,
                    self.servers[old_best_idx].server_config().addr(),
                    self.servers[best_idx].server_config().addr()
                );
            }

            time::sleep(Duration::from_secs(DEFAULT_CHECK_INTERVAL_SEC)).await;
        }
    }
}

/// Balancer with active probing
pub struct PingBalancer<C> {
    inner: Arc<PingBalancerInner<C>>,
    abortable: Arc<AbortHandle>,
}

impl<C> Drop for PingBalancer<C> {
    fn drop(&mut self) {
        self.abortable.abort();
    }
}

impl<C> PingBalancer<C> {
    pub fn best_server(&self) -> Arc<C> {
        self.inner.best_server()
    }
}

impl<C> Clone for PingBalancer<C> {
    fn clone(&self) -> Self {
        PingBalancer {
            inner: self.inner.clone(),
            abortable: self.abortable.clone(),
        }
    }
}

impl<C> Debug for PingBalancer<C>
where
    C: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PingBalancer")
            .field("servers", &self.inner.servers)
            .field("best_idx", &self.inner.best_idx.load(Ordering::Relaxed))
            .finish()
    }
}

struct PingChecker<C> {
    server: Arc<C>,
    server_type: ServerType,
    context: Arc<ServiceContext>,
}

impl<C> PingChecker<C>
where
    C: ServerIdent,
{
    /// Checks server's score and update into `ServerScore<E>`
    async fn check_update_score(self) {
        let score = match self.check_delay().await {
            Ok(d) => self.server.server_score().push_score(Score::Latency(d)).await,
            Err(..) => self.server.server_score().push_score(Score::Errored).await, // Penalty
        };

        trace!(
            "updated remote {} server {} (score: {})",
            self.server_type,
            self.server.server_config().addr(),
            score
        );
    }

    /// Detect TCP connectivity with Chromium [Network Portal Detection](https://www.chromium.org/chromium-os/chromiumos-design-docs/network-portal-detection)
    #[allow(dead_code)]
    async fn check_request_tcp_chromium(&self) -> io::Result<()> {
        static GET_BODY: &[u8] =
            b"GET /generate_204 HTTP/1.1\r\nHost: clients3.google.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("clients3.google.com".to_owned(), 80);

        let mut stream = ProxyClientStream::connect_with_opts(
            self.context.context(),
            self.server.server_config(),
            &addr,
            self.context.connect_opts_ref(),
        )
        .await?;
        stream.write_all(GET_BODY).await?;

        let mut reader = BufReader::new(stream);

        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await?;

        static EXPECTED_HTTP_STATUS_LINE: &[u8] = b"HTTP/1.1 204 No Content\r\n";
        if buf != EXPECTED_HTTP_STATUS_LINE {
            use std::io::{Error, ErrorKind};

            debug!(
                "unexpected response from http://clients3.google.com/generate_204, {:?}",
                ByteStr::new(&buf)
            );

            let err = Error::new(
                ErrorKind::InvalidData,
                "unexpected response from http://clients3.google.com/generate_204",
            );
            return Err(err);
        }

        Ok(())
    }

    /// Detect TCP connectivity with Firefox's http://detectportal.firefox.com/success.txt
    async fn check_request_tcp_firefox(&self) -> io::Result<()> {
        static GET_BODY: &[u8] =
            b"GET /success.txt HTTP/1.1\r\nHost: detectportal.firefox.com\r\nConnection: close\r\nAccept: */*\r\n\r\n";

        let addr = Address::DomainNameAddress("detectportal.firefox.com".to_owned(), 80);

        let mut stream = ProxyClientStream::connect_with_opts(
            self.context.context(),
            self.server.server_config(),
            &addr,
            self.context.connect_opts_ref(),
        )
        .await?;
        stream.write_all(GET_BODY).await?;

        let mut reader = BufReader::new(stream);

        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).await?;

        static EXPECTED_HTTP_STATUS_LINE: &[u8] = b"HTTP/1.1 200 OK\r\n";
        if buf != EXPECTED_HTTP_STATUS_LINE {
            use std::io::{Error, ErrorKind};

            debug!(
                "unexpected response from http://detectportal.firefox.com/success.txt, {:?}",
                ByteStr::new(&buf)
            );

            let err = Error::new(
                ErrorKind::InvalidData,
                "unexpected response from http://detectportal.firefox.com/success.txt",
            );
            return Err(err);
        }

        Ok(())
    }

    async fn check_request_udp(&self) -> io::Result<()> {
        // TransactionID: 0x1234
        // Flags: 0x0100 RD
        // Questions: 0x0001
        // Answer RRs: 0x0000
        // Authority RRs: 0x0000
        // Additional RRs: 0x0000
        // Queries
        //    - QNAME: \x07 firefox \x03 com \x00
        //    - QTYPE: 0x0001 A
        //    - QCLASS: 0x0001 IN
        static DNS_QUERY: &[u8] =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07firefox\x03com\x00\x00\x01\x00\x01";

        let addr = Address::SocketAddress(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53));

        let client = ProxySocket::connect_with_opts(
            self.context.context(),
            self.server.server_config(),
            self.context.connect_opts_ref(),
        )
        .await?;
        client.send(&addr, DNS_QUERY).await?;

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (n, ..) = client.recv(&mut buffer).await?;

        let dns_answer = &buffer[..n];

        // DNS packet must have at least 6 * 2 bytes
        if dns_answer.len() < 12 || &dns_answer[0..2] != b"\x12\x34" {
            use std::io::{Error, ErrorKind};

            debug!("unexpected response from 8.8.8.8:53, {:?}", ByteStr::new(&dns_answer));

            let err = Error::new(ErrorKind::InvalidData, "unexpected response from 8.8.8.8:53");
            return Err(err);
        }

        Ok(())
    }

    async fn check_request(&self) -> io::Result<()> {
        match self.server_type {
            ServerType::Tcp => self.check_request_tcp_firefox().await,
            ServerType::Udp => self.check_request_udp().await,
        }
    }

    async fn check_delay(&self) -> io::Result<u64> {
        let start = Instant::now();

        // Send HTTP GET and read the first byte
        let timeout = Duration::from_secs(DEFAULT_CHECK_TIMEOUT_SEC);
        let res = time::timeout(timeout, self.check_request()).await;

        let elapsed = Instant::now() - start;
        let elapsed = elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis()); // Converted to ms
        match res {
            Ok(Ok(..)) => {
                // Got the result ... record its time
                trace!(
                    "checked remote {} server {} latency with {} ms",
                    self.server_type,
                    self.server.server_config().addr(),
                    elapsed
                );
                Ok(elapsed)
            }
            Ok(Err(err)) => {
                debug!(
                    "failed to check {} server {}, error: {}",
                    self.server_type,
                    self.server.server_config().addr(),
                    err
                );

                // NOTE: connection / handshake error, server is down
                Err(err)
            }
            Err(..) => {
                // Timeout
                trace!(
                    "checked remote {} server {} latency timeout, elapsed {} ms",
                    self.server_type,
                    self.server.server_config().addr(),
                    elapsed
                );

                // NOTE: timeout is still available, but server is too slow
                Ok(elapsed)
            }
        }
    }
}
