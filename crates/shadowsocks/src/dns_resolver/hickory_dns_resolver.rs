//! Asynchronous DNS resolver

use std::{
    future::Future,
    io,
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::ready;
use hickory_resolver::{
    ResolveError, Resolver,
    config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
    name_server::GenericConnector,
    proto::{
        runtime::{RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd},
        udp::DnsUdpSocket,
    },
};
use log::{error, trace};
use tokio::{io::ReadBuf, net::UdpSocket};

use crate::net::{ConnectOpts, tcp::TcpStream as ShadowTcpStream, udp::UdpSocket as ShadowUdpSocket};

/// Shadowsocks hickory-dns Runtime Provider
#[derive(Clone)]
pub struct ShadowDnsRuntimeProvider {
    handle: TokioHandle,
    connect_opts: ConnectOpts,
}

impl ShadowDnsRuntimeProvider {
    fn new(connect_opts: ConnectOpts) -> Self {
        Self {
            handle: TokioHandle::default(),
            connect_opts,
        }
    }
}

impl DnsUdpSocket for ShadowUdpSocket {
    type Time = TokioTime;

    #[inline]
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<(usize, SocketAddr)>> {
        let udp: &UdpSocket = self.deref();

        let mut read_buf = ReadBuf::new(buf);
        let recv_addr = ready!(udp.poll_recv_from(cx, &mut read_buf))?;
        Ok((read_buf.filled().len(), recv_addr)).into()
    }

    #[inline]
    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], target: SocketAddr) -> Poll<io::Result<usize>> {
        let udp: &UdpSocket = self.deref();
        udp.poll_send_to(cx, buf, target)
    }
}

impl RuntimeProvider for ShadowDnsRuntimeProvider {
    type Handle = TokioHandle;
    type Tcp = AsyncIoTokioAsStd<ShadowTcpStream>;
    type Timer = TokioTime;
    type Udp = ShadowUdpSocket;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let mut connect_opts = self.connect_opts.clone();

        if let Some(bind_addr) = bind_addr {
            connect_opts.bind_local_addr = Some(bind_addr);
        }

        let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));

        Box::pin(async move {
            trace!(
                "hickory-dns RuntimeProvider tcp connecting to {} with {:?}",
                server_addr, connect_opts
            );

            let tcp = match tokio::time::timeout(
                wait_for,
                ShadowTcpStream::connect_with_opts(&server_addr, &connect_opts),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(err)) => return Err(err),
                Err(_) => return Err(io::ErrorKind::TimedOut.into()),
            };

            trace!(
                "hickory-dns RuntimeProvider tcp connected to {}, {:?}",
                server_addr, connect_opts
            );
            Ok(AsyncIoTokioAsStd(tcp))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let connect_opts = self.connect_opts.clone();
        Box::pin(async move {
            trace!(
                "hickory-dns RuntimeProvider udp binding to {} with {:?}",
                local_addr, connect_opts
            );
            let udp = ShadowUdpSocket::bind_with_opts(&local_addr, &connect_opts).await?;
            trace!(
                "hickory-dns RuntimeProvider udp bound to {}, {:?}",
                local_addr, connect_opts
            );
            Ok(udp)
        })
    }
}

/// Shadowsocks DNS ConnectionProvider
pub type ShadowDnsConnectionProvider = GenericConnector<ShadowDnsRuntimeProvider>;

/// Shadowsocks DNS resolver
///
/// A customized hickory-dns-resolver
pub type DnsResolver = Resolver<ShadowDnsConnectionProvider>;

/// Create a `hickory-dns` asynchronous DNS resolver
pub async fn create_resolver(
    dns: Option<ResolverConfig>,
    opts: Option<ResolverOpts>,
    connect_opts: ConnectOpts,
) -> Result<DnsResolver, ResolveError> {
    // Customized dns resolution
    match dns {
        Some(conf) => {
            trace!("initializing DNS resolver with config {:?}", conf,);

            let mut builder = DnsResolver::builder_with_config(
                conf,
                ShadowDnsConnectionProvider::new(ShadowDnsRuntimeProvider::new(connect_opts)),
            );
            if let Some(opts) = opts {
                *builder.options_mut() = opts;
            }
            let resolver_opts = builder.options_mut();

            // Use Ipv4AndIpv6 strategy. Because Ipv4ThenIpv6 or Ipv6ThenIpv4 will return if the first query returned.
            // Since we want to use Happy Eyeballs to connect to both IPv4 and IPv6 addresses, we need both A and AAAA records.
            resolver_opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

            // Enable EDNS0 for large records
            resolver_opts.edns0 = true;

            trace!("initializing DNS resolver with opts {:?}", resolver_opts);

            Ok(builder.build())
        }

        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration
        // Android doesn't have /etc/resolv.conf.
        None => {
            match DnsResolver::builder(ShadowDnsConnectionProvider::new(ShadowDnsRuntimeProvider::new(
                connect_opts,
            ))) {
                Ok(mut builder) => {
                    let opts = builder.options_mut();
                    // NOTE: timeout will be set by config (for example, /etc/resolv.conf on UNIX-like system)
                    //
                    // Only ip_strategy should be changed. Why Ipv4AndIpv6? See comments above.
                    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

                    // Enable EDNS0 for large records
                    opts.edns0 = true;

                    trace!("initializing DNS resolver with system-config opts {:?}", opts);

                    Ok(builder.build())
                }
                Err(err) => {
                    error!("initialize DNS resolver with system-config failed, error: {}", err);
                    Err(ResolveError::from(
                        "current platform doesn't support hickory-dns resolver with system configured".to_owned(),
                    ))
                }
            }
        }
    }
}
