//! UDP Tunnel server

use std::{
    io::{self, Cursor},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use bytes::{BufMut, Bytes, BytesMut};
use futures::future::{self, AbortHandle};
use io::ErrorKind;
use log::{debug, error, info, trace, warn};
use lru_time_cache::{Entry, LruCache};
use shadowsocks::{
    lookup_then,
    net::UdpSocket as ShadowUdpSocket,
    relay::{
        socks5::{Address, UdpAssociateHeader},
        udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
};
use spin::Mutex as SpinMutex;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    time,
};

use crate::{
    config::ClientConfig,
    local::{context::ServiceContext, loadbalancing::PingBalancer},
    net::MonProxySocket,
};

pub struct Socks5UdpServer {
    context: Arc<ServiceContext>,
    assoc_map: Arc<Mutex<LruCache<SocketAddr, Arc<UdpAssociation>>>>,
    cleanup_abortable: AbortHandle,
}

impl Drop for Socks5UdpServer {
    fn drop(&mut self) {
        self.cleanup_abortable.abort();
    }
}

impl Socks5UdpServer {
    pub fn new(
        context: Arc<ServiceContext>,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
    ) -> Socks5UdpServer {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = Arc::new(Mutex::new(match capacity {
            Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            None => LruCache::with_expiry_duration(time_to_live),
        }));

        let cleanup_abortable = {
            let assoc_map = assoc_map.clone();
            let (cleanup_task, cleanup_abortable) = future::abortable(async move {
                let mut interval = time::interval(time_to_live);
                loop {
                    interval.tick().await;

                    // iter() will trigger a cleanup of expired associations
                    let _ = assoc_map.lock().await.iter();
                }
            });
            tokio::spawn(cleanup_task);
            cleanup_abortable
        };

        Socks5UdpServer {
            context,
            assoc_map,
            cleanup_abortable,
        }
    }

    pub async fn run(&mut self, client_config: &ClientConfig, balancer: PingBalancer) -> io::Result<()> {
        let socket = match *client_config {
            ClientConfig::SocketAddr(ref saddr) => ShadowUdpSocket::bind(&saddr).await?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(&self.context.context_ref(), dname, port, |addr| {
                    ShadowUdpSocket::bind(&addr).await
                })?
                .1
            }
        };
        let socket: UdpSocket = socket.into();

        info!("shadowsocks socks5 UDP listening on {}", socket.local_addr()?);

        let listener = Arc::new(socket);

        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, peer_addr) = match listener.recv_from(&mut buffer).await {
                Ok(s) => s,
                Err(err) => {
                    error!("udp server recv_from failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // PKT = UdpAssociateHeader + PAYLOAD
            let mut cur = Cursor::new(data);
            let header = match UdpAssociateHeader::read_from(&mut cur).await {
                Ok(h) => h,
                Err(..) => {
                    error!("received invalid UDP associate packet: {:?}", ByteStr::new(data));
                    continue;
                }
            };

            if header.frag != 0 {
                error!("received UDP associate with frag != 0, which is not supported by shadowsocks");
                continue;
            }

            let pos = cur.position() as usize;
            let payload = &data[pos..];

            trace!(
                "UDP ASSOCIATE {} -> {}, {} bytes",
                peer_addr,
                header.address,
                payload.len()
            );

            if let Err(err) = self
                .send_packet(&listener, peer_addr, header.address, &balancer, payload)
                .await
            {
                error!(
                    "udp packet from {} relay {} bytes failed, error: {}",
                    peer_addr,
                    data.len(),
                    err
                );
            }
        }
    }

    async fn send_packet(
        &mut self,
        listener: &Arc<UdpSocket>,
        peer_addr: SocketAddr,
        target_addr: Address,
        balancer: &PingBalancer,
        data: &[u8],
    ) -> io::Result<()> {
        let assoc = match self.assoc_map.lock().await.entry(peer_addr) {
            Entry::Occupied(occ) => occ.into_mut().clone(),
            Entry::Vacant(vac) => {
                let assoc = UdpAssociation::new(
                    self.context.clone(),
                    listener.clone(),
                    peer_addr,
                    self.assoc_map.clone(),
                    balancer.clone(),
                );
                vac.insert(assoc.clone());
                assoc
            }
        };

        if let Err(..) = assoc.sender.try_send((target_addr, Bytes::copy_from_slice(data))) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err);
        }

        Ok(())
    }
}

struct UdpAssociation {
    context: Arc<ServiceContext>,
    inbound: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    sender: mpsc::Sender<(Address, Bytes)>,
    bypassed_ipv4_socket: SpinMutex<Option<Arc<UdpSocket>>>,
    bypassed_ipv6_socket: SpinMutex<Option<Arc<UdpSocket>>>,
    proxied_socket: SpinMutex<Option<Arc<MonProxySocket>>>,
    assoc_map: Arc<Mutex<LruCache<SocketAddr, Arc<UdpAssociation>>>>,
    balancer: PingBalancer,
    abortables: SpinMutex<Vec<AbortHandle>>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        for ab in self.abortables.lock().iter() {
            ab.abort();
        }
    }
}

impl UdpAssociation {
    fn new(
        context: Arc<ServiceContext>,
        inbound: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        assoc_map: Arc<Mutex<LruCache<SocketAddr, Arc<UdpAssociation>>>>,
        balancer: PingBalancer,
    ) -> Arc<UdpAssociation> {
        // Pending packets 64 should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping exccess packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(64);

        let assoc = Arc::new(UdpAssociation {
            context,
            inbound,
            peer_addr,
            sender,
            bypassed_ipv4_socket: SpinMutex::new(None),
            bypassed_ipv6_socket: SpinMutex::new(None),
            proxied_socket: SpinMutex::new(None),
            assoc_map,
            balancer,
            abortables: SpinMutex::new(Vec::new()),
        });

        let (l2r_task, l2r_abortable) = {
            let assoc = assoc.clone();
            future::abortable(assoc.copy_l2r(receiver))
        };
        tokio::spawn(l2r_task);

        assoc.abortables.lock().push(l2r_abortable);
        assoc
    }

    async fn copy_l2r(self: Arc<Self>, mut receiver: mpsc::Receiver<(Address, Bytes)>) {
        while let Some((target_addr, data)) = receiver.recv().await {
            let bypassed = self.context.check_target_bypassed(&target_addr).await;

            trace!(
                "udp relay {} -> {} ({}) with {} bytes",
                self.peer_addr,
                target_addr,
                if bypassed { "bypassed" } else { "proxied" },
                data.len()
            );

            let assoc = self.clone();
            if bypassed {
                if let Err(err) = assoc.copy_bypassed_l2r(&target_addr, &data).await {
                    error!(
                        "udp relay {} -> {} (bypassed) with {} bytes, error: {}",
                        self.peer_addr,
                        target_addr,
                        data.len(),
                        err
                    );
                }
            } else {
                if let Err(err) = assoc.copy_proxied_l2r(&target_addr, &data).await {
                    error!(
                        "udp relay {} -> {} (proxied) with {} bytes, error: {}",
                        self.peer_addr,
                        target_addr,
                        data.len(),
                        err
                    );
                }
            }
        }
    }

    async fn copy_bypassed_l2r(self: Arc<Self>, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        match *target_addr {
            Address::SocketAddress(sa) => match sa {
                SocketAddr::V4(..) => self.copy_bypassed_ipv4_l2r(sa, data).await,
                SocketAddr::V6(..) => self.copy_bypassed_ipv6_l2r(sa, data).await,
            },
            Address::DomainNameAddress(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |sa| {
                    match sa {
                        SocketAddr::V4(..) => self.clone().copy_bypassed_ipv4_l2r(sa, data).await,
                        SocketAddr::V6(..) => self.clone().copy_bypassed_ipv6_l2r(sa, data).await,
                    }
                })
                .map(|_| ())
            }
        }
    }

    async fn copy_bypassed_ipv4_l2r(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let mut bypassed_socket = self.bypassed_ipv4_socket.lock();

        if bypassed_socket.is_none() {
            // Initialize bypass task

            let socket = ShadowUdpSocket::bind_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
            let socket: Arc<UdpSocket> = Arc::new(socket.into());

            let (r2l_fut, r2l_abortable) = {
                let assoc = self.clone();
                future::abortable(assoc.copy_bypassed_r2l(socket.clone()))
            };

            // CLIENT <- REMOTE
            tokio::spawn(r2l_fut);
            debug!(
                "created udp association for {} (bypassed) with {:?}",
                self.peer_addr,
                self.context.connect_opts_ref()
            );
            *bypassed_socket = Some(socket);
            self.abortables.lock().push(r2l_abortable);
        }

        let socket = bypassed_socket.as_ref().unwrap();
        let n = socket.send_to(data, target_addr).await?;
        if n != data.len() {
            warn!(
                "{} -> {} sent {} bytes != expected {} bytes",
                self.peer_addr,
                target_addr,
                n,
                data.len()
            );
        }

        Ok(())
    }

    async fn copy_bypassed_ipv6_l2r(self: Arc<Self>, target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        let mut bypassed_socket = self.bypassed_ipv6_socket.lock();

        if bypassed_socket.is_none() {
            // Initialize bypass task

            let socket = ShadowUdpSocket::bind_with_opts(&target_addr, self.context.connect_opts_ref()).await?;
            let socket: Arc<UdpSocket> = Arc::new(socket.into());

            let (r2l_fut, r2l_abortable) = {
                let assoc = self.clone();
                future::abortable(assoc.copy_bypassed_r2l(socket.clone()))
            };

            // CLIENT <- REMOTE
            tokio::spawn(r2l_fut);

            debug!(
                "created udp association for {} (bypassed) with {:?}",
                self.peer_addr,
                self.context.connect_opts_ref()
            );
            *bypassed_socket = Some(socket);
            self.abortables.lock().push(r2l_abortable);
        }

        let socket = bypassed_socket.as_ref().unwrap();
        let n = socket.send_to(data, target_addr).await?;
        if n != data.len() {
            warn!(
                "{} -> {} sent {} bytes != expected {} bytes",
                self.peer_addr,
                target_addr,
                n,
                data.len()
            );
        }

        Ok(())
    }

    async fn copy_proxied_l2r(self: Arc<Self>, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        let mut proxied_socket = self.proxied_socket.lock();

        if proxied_socket.is_none() {
            // Initialize proxied socket

            let server = self.balancer.best_udp_server();
            let svr_cfg = server.server_config();

            let socket =
                ProxySocket::connect_with_opts(self.context.context(), svr_cfg, self.context.connect_opts_ref())
                    .await?;
            let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
            let socket = Arc::new(socket);

            let (r2l_fut, r2l_abortable) = {
                let assoc = self.clone();
                future::abortable(assoc.copy_proxied_r2l(socket.clone()))
            };

            // CLIENT <- REMOTE
            tokio::spawn(r2l_fut);

            debug!(
                "created udp association for {} <-> {} (proxied) with {:?}",
                self.peer_addr,
                svr_cfg.addr(),
                self.context.connect_opts_ref()
            );
            *proxied_socket = Some(socket);
            self.abortables.lock().push(r2l_abortable);
        }

        let socket = proxied_socket.as_ref().unwrap();
        socket.send(target_addr, data).await?;

        Ok(())
    }

    async fn copy_proxied_r2l(self: Arc<Self>, outbound: Arc<MonProxySocket>) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let mut payload_buffer = BytesMut::new();
        loop {
            let (n, addr) = match outbound.recv(&mut buffer).await {
                Ok(n) => {
                    // Keep association alive in map
                    let _ = self.assoc_map.lock().await.get(&self.peer_addr);
                    n
                }
                Err(err) => {
                    error!(
                        "udp failed to receive from proxied outbound socket, peer_addr: {}, error: {}",
                        self.peer_addr, err
                    );
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];
            payload_buffer.clear();

            // Resssemble packet
            let header = UdpAssociateHeader::new(0, addr.clone());
            payload_buffer.reserve(header.serialized_len() + n);

            header.write_to_buf(&mut payload_buffer);
            payload_buffer.put_slice(data);

            // Send back to client
            if let Err(err) = self.inbound.send_to(&payload_buffer, self.peer_addr).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    self.peer_addr, addr, err
                );
            }

            trace!(
                "udp relay {} <- {} with {} bytes",
                self.peer_addr,
                addr,
                payload_buffer.len()
            );
        }
    }

    async fn copy_bypassed_r2l(self: Arc<Self>, outbound: Arc<UdpSocket>) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, addr) = match outbound.recv_from(&mut buffer).await {
                Ok(n) => {
                    // Keep association alive in map
                    let _ = self.assoc_map.lock().await.get(&self.peer_addr);
                    n
                }
                Err(err) => {
                    error!(
                        "udp failed to receive from bypass outbound socket, peer_addr: {}, error: {}",
                        self.peer_addr, err
                    );
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let data = &buffer[..n];

            // Send back to client
            if let Err(err) = self.inbound.send_to(data, self.peer_addr).await {
                warn!(
                    "udp failed to send back to client {}, from target {}, error: {}",
                    self.peer_addr, addr, err
                );
            }

            trace!("udp relay {} <- {} with {} bytes", self.peer_addr, addr, data.len());
        }
    }
}
