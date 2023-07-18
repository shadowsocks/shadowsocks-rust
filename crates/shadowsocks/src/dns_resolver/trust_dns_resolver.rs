//! Asynchronous DNS resolver

use std::{
    future::Future,
    io,
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};

use cfg_if::cfg_if;
use futures::ready;
use log::trace;
use tokio::{io::ReadBuf, net::UdpSocket};
use trust_dns_resolver::{
    config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
    error::ResolveResult,
    name_server::{GenericConnector, RuntimeProvider},
    proto::{iocompat::AsyncIoTokioAsStd, udp::DnsUdpSocket, TokioTime},
    AsyncResolver,
    TokioHandle,
};

use crate::net::{tcp::TcpStream as ShadowTcpStream, udp::UdpSocket as ShadowUdpSocket, ConnectOpts};

/// Shadowsocks trust-dns Runtime Provider
#[derive(Clone)]
pub struct ShadowDnsRuntimeProvider {
    handle: TokioHandle,
    connect_opts: ConnectOpts,
}

impl ShadowDnsRuntimeProvider {
    fn new(connect_opts: ConnectOpts) -> ShadowDnsRuntimeProvider {
        ShadowDnsRuntimeProvider {
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

    fn connect_tcp(&self, server_addr: SocketAddr) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let connect_opts = self.connect_opts.clone();
        Box::pin(async move {
            let tcp = ShadowTcpStream::connect_with_opts(&server_addr, &connect_opts).await?;
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
            let udp = ShadowUdpSocket::bind_with_opts(&local_addr, &connect_opts).await?;
            Ok(udp)
        })
    }
}

/// Shadowsocks DNS ConnectionProvider
pub type ShadowDnsConnectionProvider = GenericConnector<ShadowDnsRuntimeProvider>;

/// Shadowsocks DNS resolver
///
/// A customized trust-dns-resolver
pub type DnsResolver = AsyncResolver<ShadowDnsConnectionProvider>;

/// Create a `trust-dns` asynchronous DNS resolver
pub async fn create_resolver(
    dns: Option<ResolverConfig>,
    dns_cache_size: Option<usize>,
    connect_opts: ConnectOpts,
) -> ResolveResult<DnsResolver> {
    // Customized dns resolution
    match dns {
        Some(conf) => {
            let mut resolver_opts = ResolverOpts::default();
            // Use Ipv4AndIpv6 strategy. Because Ipv4ThenIpv6 or Ipv6ThenIpv4 will return if the first query returned.
            // Since we want to use Happy Eyeballs to connect to both IPv4 and IPv6 addresses, we need both A and AAAA records.
            resolver_opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

            if let Some(size) = dns_cache_size {
                resolver_opts.cache_size = size
            }

            trace!(
                "initializing DNS resolver with config {:?} opts {:?}",
                conf,
                resolver_opts
            );
            Ok(DnsResolver::new(
                conf,
                resolver_opts,
                ShadowDnsConnectionProvider::new(ShadowDnsRuntimeProvider::new(connect_opts)),
            ))
        }

        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration
        // Android doesn't have /etc/resolv.conf.
        None => {
            cfg_if! {
                if #[cfg(any(all(unix, not(target_os = "android")), windows))] {
                    use trust_dns_resolver::system_conf::read_system_conf;

                    // use the system resolver configuration
                    let (config, mut opts) = match read_system_conf() {
                        Ok(o) => o,
                        Err(err) => {
                            use log::error;

                            error!("failed to initialize DNS resolver with system-config, error: {}", err);

                            // From::from is required because on error type is different on Windows
                            #[allow(clippy::useless_conversion)]
                            return Err(From::from(err));
                        }
                    };

                    // NOTE: timeout will be set by config (for example, /etc/resolv.conf on UNIX-like system)
                    //
                    // Only ip_strategy should be changed. Why Ipv4AndIpv6? See comments above.
                    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

                    trace!(
                        "initializing DNS resolver with system-config {:?} opts {:?}",
                        config,
                        opts
                    );

                    Ok(DnsResolver::new(config, opts, ShadowDnsConnectionProvider::new(ShadowDnsRuntimeProvider::new(connect_opts))))
                } else {
                    use trust_dns_resolver::error::ResolveError;

                    Err(ResolveError::from("current platform doesn't support trust-dns resolver with system configured".to_owned()))
                }
            }
        }
    }
}
