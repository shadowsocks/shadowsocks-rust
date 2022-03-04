//! UDP transparent proxy

use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use log::{error, info, trace, warn};
use lru_time_cache::LruCache;
use shadowsocks::{
    lookup_then,
    net::ConnectOpts,
    relay::{socks5::Address, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
    ServerAddr,
};
use tokio::{sync::Mutex, task::JoinHandle, time};

use crate::{
    config::RedirType,
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UdpAssociationManager, UdpInboundWrite},
        redir::redir_ext::{RedirSocketOpts, UdpSocketRedirExt},
        utils::to_ipv4_mapped,
    },
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
    fn new() -> UdpRedirInboundCache {
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

        UdpRedirInboundCache { cache, watcher }
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
    fn new(redir_ty: RedirType, opts: &ConnectOpts) -> UdpRedirInboundWriter {
        UdpRedirInboundWriter {
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

#[async_trait]
impl UdpInboundWrite for UdpRedirInboundWriter {
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        let addr = match *remote_addr {
            Address::SocketAddress(sa) => {
                // Try to convert IPv4 mapped IPv6 address if server is running on dual-stack mode
                match sa {
                    SocketAddr::V4(..) => sa,
                    SocketAddr::V6(ref v6) => match to_ipv4_mapped(v6.ip()) {
                        Some(v4) => SocketAddr::new(IpAddr::from(v4), v6.port()),
                        None => sa,
                    },
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
            if let Some(socket) = cache.get(&addr) {
                socket.clone()
            } else {
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
        };

        // Send back to client
        inbound.send_to(data, peer_addr).await.map(|n| {
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
                n,
                remote_addr,
                peer_addr,
                self.socket_opts
            );
        })
    }
}

pub struct UdpRedir {
    context: Arc<ServiceContext>,
    redir_ty: RedirType,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
}

impl UdpRedir {
    pub fn new(
        context: Arc<ServiceContext>,
        redir_ty: RedirType,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
    ) -> UdpRedir {
        UdpRedir {
            context,
            redir_ty,
            time_to_live,
            capacity,
        }
    }

    pub async fn run(&self, client_config: &ServerAddr, balancer: PingBalancer) -> io::Result<()> {
        let listener = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => UdpRedirSocket::listen(self.redir_ty, *saddr)?,
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |addr| {
                    UdpRedirSocket::listen(self.redir_ty, addr)
                })?
                .1
            }
        };

        let local_addr = listener.local_addr().expect("determine port bound to");
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
            balancer,
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

                recv_result = listener.recv_dest_from(&mut pkt_buf) => {
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
                        error!(
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
