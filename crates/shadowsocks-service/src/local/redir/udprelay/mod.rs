//! UDP transparent proxy

use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use log::{debug, error, info, trace, warn};
use lru_time_cache::LruCache;
use shadowsocks::{
    ServerAddr, lookup_then,
    net::{ConnectOpts, get_ip_stack_capabilities},
    relay::{socks5::Address, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
};
use tokio::{sync::Mutex, task::JoinHandle, time};

use crate::{
    config::RedirType,
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UdpAssociationManager, UdpInboundWrite},
        redir::redir_ext::{RedirSocketOpts, UdpSocketRedirExt},
    },
    net::utils::to_ipv4_mapped,
};

use self::sys::UdpRedirSocket;

mod sys;

const INBOUND_SOCKET_CACHE_EXPIRATION: Duration = Duration::from_secs(60);
const INBOUND_SOCKET_CACHE_CAPACITY: usize = 256;

struct UdpRedirInboundCache {
    cache: Arc<Mutex<LruCache<SocketAddr, Arc<UdpRedirSocket>>>>,
    watcher: JoinHandle<()>,
}

impl Drop for UdpRedirInboundCache {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

impl UdpRedirInboundCache {
    fn new() -> Self {
        let cache = Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(
            INBOUND_SOCKET_CACHE_EXPIRATION,
            INBOUND_SOCKET_CACHE_CAPACITY,
        )));

        let watcher = {
            let cache = cache.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(INBOUND_SOCKET_CACHE_EXPIRATION).await;
                    let _ = cache.lock().await.iter();
                }
            })
        };

        Self { cache, watcher }
    }
}

#[derive(Clone)]
struct UdpRedirInboundWriter {
    redir_ty: RedirType,
    socket_opts: RedirSocketOpts,
    inbound_cache: Arc<UdpRedirInboundCache>,
}

impl UdpRedirInboundWriter {
    #[allow(unused_variables, clippy::needless_update)]
    fn new(redir_ty: RedirType, opts: &ConnectOpts) -> Self {
        Self {
            redir_ty,
            socket_opts: RedirSocketOpts {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                fwmark: opts.fwmark,

                ..Default::default()
            },
            inbound_cache: Arc::new(UdpRedirInboundCache::new()),
        }
    }
}

impl UdpInboundWrite for UdpRedirInboundWriter {
    async fn send_to(&self, mut peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        // If IPv6 Transparent Proxy is supported on the current platform,
        // then we should always use IPv6 sockets for sending IPv4 packets.
        let ip_stack_caps = get_ip_stack_capabilities();

        let addr = match *remote_addr {
            Address::SocketAddress(sa) => {
                match sa {
                    SocketAddr::V4(ref v4) => {
                        // If IPv4-mapped-IPv6 is supported.
                        // Converts IPv4 address to IPv4-mapped-IPv6
                        // All sockets will be created in IPv6 (nearly all modern OS supports IPv6 sockets)
                        if ip_stack_caps.support_ipv4_mapped_ipv6 {
                            SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
                        } else {
                            sa
                        }
                    }
                    SocketAddr::V6(ref v6) => {
                        // If IPv6 is not supported. Try to map it back to IPv4.
                        if !ip_stack_caps.support_ipv6 || !ip_stack_caps.support_ipv4_mapped_ipv6 {
                            match v6.ip().to_ipv4_mapped() {
                                Some(v4) => SocketAddr::new(v4.into(), v6.port()),
                                None => sa,
                            }
                        } else {
                            sa
                        }
                    }
                }
            }
            Address::DomainNameAddress(..) => {
                let err = io::Error::new(
                    ErrorKind::InvalidInput,
                    "redir destination must not be an domain name address",
                );
                return Err(err);
            }
        };

        let inbound = {
            let mut cache = self.inbound_cache.cache.lock().await;
            match cache.get(&addr) {
                Some(socket) => socket.clone(),
                _ => {
                    // Create a socket binds to destination addr
                    // This only works for systems that supports binding to non-local addresses
                    //
                    // This socket has to set SO_REUSEADDR and SO_REUSEPORT.
                    // Outbound addresses could be connected from different source addresses.
                    let inbound = UdpRedirSocket::bind_nonlocal(self.redir_ty, addr, &self.socket_opts)?;

                    // UDP socket could be shared between threads and is safe to be manipulated by multiple threads
                    let inbound = Arc::new(inbound);
                    cache.insert(addr, inbound.clone());

                    inbound
                }
            }
        };

        // Convert peer_addr (client)'s address family to match remote_addr (target)
        match (addr, peer_addr) {
            (SocketAddr::V4(..), SocketAddr::V4(..)) | (SocketAddr::V6(..), SocketAddr::V6(..)) => {}
            (SocketAddr::V4(..), SocketAddr::V6(v6_peer_addr)) => {
                if let Some(v4_ip) = v6_peer_addr.ip().to_ipv4_mapped() {
                    peer_addr = SocketAddr::new(v4_ip.into(), v6_peer_addr.port());
                } else {
                    warn!(
                        "udp redir send back {} bytes, remote: {}, peer: {}, protocol not match",
                        data.len(),
                        addr,
                        peer_addr
                    );
                }
            }
            (SocketAddr::V6(..), SocketAddr::V4(v4_peer_addr)) => {
                peer_addr = SocketAddr::new(v4_peer_addr.ip().to_ipv6_mapped().into(), v4_peer_addr.port());
            }
        }

        match inbound.send_to(data, peer_addr).await {
            Ok(n) => {
                if n < data.len() {
                    warn!(
                        "udp redir send back data (actual: {} bytes, sent: {} bytes), remote: {}, peer: {}",
                        n,
                        data.len(),
                        remote_addr,
                        peer_addr
                    );
                }

                trace!(
                    "udp redir send back data {} bytes, remote: {}, peer: {}, socket_opts: {:?}",
                    n, remote_addr, peer_addr, self.socket_opts
                );

                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

pub struct RedirUdpServer {
    context: Arc<ServiceContext>,
    redir_ty: RedirType,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
    listener: UdpRedirSocket,
    balancer: PingBalancer,
}

impl RedirUdpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        redir_ty: RedirType,
        client_config: &ServerAddr,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        balancer: PingBalancer,
    ) -> io::Result<Self> {
        let listener = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => UdpRedirSocket::listen(redir_ty, *saddr)?,
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, port, |addr| {
                    UdpRedirSocket::listen(redir_ty, addr)
                })?
                .1
            }
        };

        Ok(Self {
            context,
            redir_ty,
            time_to_live,
            capacity,
            listener,
            balancer,
        })
    }

    pub async fn run(self) -> io::Result<()> {
        let local_addr = self.listener.local_addr().expect("determine port bound to");
        info!(
            "shadowsocks UDP redirect ({}) listening on {}",
            self.redir_ty, local_addr
        );

        #[allow(clippy::needless_update)]
        let (mut manager, cleanup_interval, mut keepalive_rx) = UdpAssociationManager::new(
            self.context.clone(),
            UdpRedirInboundWriter::new(self.redir_ty, self.context.connect_opts_ref()),
            self.time_to_live,
            self.capacity,
            self.balancer,
        );

        let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut cleanup_timer = time::interval(cleanup_interval);

        loop {
            tokio::select! {
                _ = cleanup_timer.tick() => {
                    // cleanup expired associations. iter() will remove expired elements
                    manager.cleanup_expired().await;
                }

                peer_addr_opt = keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("keep-alive channel closed unexpectly");
                    manager.keep_alive(&peer_addr).await;
                }

                recv_result = self.listener.recv_dest_from(&mut pkt_buf) => {
                    let (recv_len, src, mut dst) = match recv_result {
                        Ok(o) => o,
                        Err(err) => {
                            error!("recv_dest_from failed with err: {}", err);
                            continue;
                        }
                    };

                    // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
                    // Copy bytes, because udp_associate runs in another tokio Task
                    let pkt = &pkt_buf[..recv_len];

                    trace!(
                        "received UDP packet from {}, destination {}, length {} bytes",
                        src,
                        dst,
                        recv_len
                    );

                    if recv_len == 0 {
                        // For windows, it will generate a ICMP Port Unreachable Message
                        // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
                        // Which will result in recv_from return 0.
                        //
                        // It cannot be solved here, because `WSAGetLastError` is already set.
                        //
                        // See `relay::udprelay::utils::create_socket` for more detail.
                        continue;
                    }

                    // Try to convert IPv4 mapped IPv6 address for dual-stack mode.
                    if let SocketAddr::V6(ref a) = dst {
                        if let Some(v4) = to_ipv4_mapped(a.ip()) {
                            dst = SocketAddr::new(IpAddr::from(v4), a.port());
                        }
                    }

                    if let Err(err) = manager.send_to(src, Address::from(dst), pkt).await {
                        debug!(
                            "udp packet relay {} -> {} with {} bytes failed, error: {}",
                            src,
                            dst,
                            pkt.len(),
                            err
                        );
                    }
                }
            }
        }
    }
}
