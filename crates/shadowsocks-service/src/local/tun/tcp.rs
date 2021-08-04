use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use etherparse::TcpHeader;
use ipnet::IpNet;
use log::{debug, error, trace};
use lru_time_cache::LruCache;
use shadowsocks::{net::TcpListener, relay::socks5::Address};
use tokio::{net::TcpStream, sync::Mutex, task::JoinHandle};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::AutoProxyClientStream,
    utils::{establish_tcp_tunnel, to_ipv4_mapped},
};

struct TcpAddressTranslator {
    connections: LruCache<SocketAddr, TcpConnection>,
    mapping: LruCache<(SocketAddr, SocketAddr), SocketAddr>,
}

impl TcpAddressTranslator {
    fn new() -> TcpAddressTranslator {
        TcpAddressTranslator {
            connections: LruCache::with_expiry_duration(Duration::from_secs(24 * 60 * 60)),
            mapping: LruCache::with_expiry_duration(Duration::from_secs(24 * 60 * 60)),
        }
    }
}

pub struct TcpTun {
    tcp_daddr: SocketAddr,
    free_addrs: Vec<IpAddr>,
    translator: Arc<Mutex<TcpAddressTranslator>>,
    abortable: JoinHandle<io::Result<()>>,
}

impl Drop for TcpTun {
    fn drop(&mut self) {
        self.abortable.abort();
    }
}

impl TcpTun {
    pub async fn new(context: Arc<ServiceContext>, tun_network: IpNet, balancer: PingBalancer) -> io::Result<TcpTun> {
        let mut hosts = tun_network.hosts();
        let tcp_daddr = match hosts.next() {
            Some(d) => d,
            None => return Err(io::Error::new(ErrorKind::Other, "tun network doesn't have any hosts")),
        };

        // Take up to 10 IPs as saddr for NAT allocating
        let free_addrs = hosts.take(10).collect::<Vec<IpAddr>>();
        assert!(!free_addrs.is_empty());

        debug!("tun tcp listener bind {}", tcp_daddr);

        let listener = TcpListener::bind_with_opts(&SocketAddr::new(tcp_daddr, 0), context.accept_opts()).await?;
        let tcp_daddr = listener.local_addr()?;

        let translator = Arc::new(Mutex::new(TcpAddressTranslator::new()));

        let abortable = {
            let translator = translator.clone();
            tokio::spawn(TcpTun::tunnel(context, listener, balancer, translator))
        };

        Ok(TcpTun {
            tcp_daddr,
            free_addrs,
            translator,
            abortable,
        })
    }

    pub async fn handle_packet(
        &mut self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp_header: &TcpHeader,
    ) -> io::Result<Option<(SocketAddr, SocketAddr)>> {
        let TcpAddressTranslator {
            ref mut connections,
            ref mut mapping,
        } = *(self.translator.lock().await);

        let (conn, is_reply) = if tcp_header.syn && !tcp_header.ack {
            // 1st SYN, creating a new connection
            // Allocate a `saddr` for it
            let saddr = loop {
                let addr_idx = rand::random::<usize>() % self.free_addrs.len();
                let port = rand::random::<u16>() % (65535 - 1024) + 1024;

                let addr = SocketAddr::new(self.free_addrs[addr_idx], port);
                if !connections.contains_key(&addr) {
                    trace!("allocated tcp addr {} for {} -> {}", addr, src_addr, dst_addr);

                    // Create one in the connection map.
                    connections.insert(
                        addr,
                        TcpConnection {
                            saddr: src_addr,
                            daddr: dst_addr,
                            faked_saddr: addr,
                            state: TcpState::Established,
                        },
                    );

                    // Record the fake address mapping
                    mapping.insert((src_addr, dst_addr), addr);

                    break addr;
                }
            };

            (connections.get_mut(&saddr).unwrap(), false)
        } else {
            // Find if it is an existed connection, ignore it otherwise
            match mapping.get(&(src_addr, dst_addr)) {
                Some(saddr) => match connections.get_mut(saddr) {
                    Some(c) => (c, false),
                    None => {
                        debug!("unknown tcp connection {} -> {}", src_addr, dst_addr);
                        return Ok(None);
                    }
                },
                None => {
                    // Check if it is a reply packet
                    match connections.get_mut(&dst_addr) {
                        Some(c) => (c, true),
                        None => {
                            debug!("unknown tcp connection {} -> {}", src_addr, dst_addr);
                            return Ok(None);
                        }
                    }
                }
            }
        };

        let (trans_saddr, trans_daddr) = if is_reply {
            trace!("TCP {} <- {} {:?}", conn.saddr, conn.daddr, tcp_header);
            (conn.daddr, conn.saddr)
        } else {
            trace!("TCP {} -> {} {:?}", conn.saddr, conn.daddr, tcp_header);
            (conn.faked_saddr, self.tcp_daddr)
        };

        if tcp_header.rst || (tcp_header.ack && conn.state == TcpState::LastAck) {
            // Connection closed.
            trace!("tcp connection closed {} -> {}", conn.saddr, conn.daddr);

            mapping.remove(&(src_addr, dst_addr));
            let faked_saddr = conn.faked_saddr;
            connections.remove(&faked_saddr);
        } else if tcp_header.fin {
            match conn.state {
                TcpState::Established => conn.state = TcpState::FinWait,
                TcpState::FinWait => conn.state = TcpState::LastAck,
                _ => {}
            }
        }

        Ok(Some((trans_saddr, trans_daddr)))
    }

    async fn tunnel(
        context: Arc<ServiceContext>,
        listener: TcpListener,
        balancer: PingBalancer,
        translator: Arc<Mutex<TcpAddressTranslator>>,
    ) -> io::Result<()> {
        loop {
            let (stream, peer_addr) = listener.accept().await?;

            // Try to translate
            let (saddr, daddr) = {
                let mut translator = translator.lock().await;
                match translator.connections.get(&peer_addr) {
                    Some(c) => (c.saddr, c.daddr),
                    None => {
                        error!("unknown connection from {}", peer_addr);
                        continue;
                    }
                }
            };

            debug!("establishing tcp tunnel {} -> {}", saddr, daddr);

            let context = context.clone();
            let balancer = balancer.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_redir_client(context, balancer, stream, peer_addr, daddr).await {
                    debug!("TCP redirect client, error: {:?}", err);
                }
            });
        }
    }
}

/// Established Client Transparent Proxy
///
/// This method must be called after handshaking with client (for example, socks5 handshaking)
async fn establish_client_tcp_redir<'a>(
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    addr: &Address,
) -> io::Result<()> {
    let server = balancer.best_tcp_server();
    let svr_cfg = server.server_config();

    let mut remote = AutoProxyClientStream::connect(context, &server, addr).await?;

    establish_tcp_tunnel(svr_cfg, &mut stream, &mut remote, peer_addr, addr).await
}

async fn handle_redir_client(
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    s: TcpStream,
    peer_addr: SocketAddr,
    mut daddr: SocketAddr,
) -> io::Result<()> {
    // Get forward address from socket
    //
    // Try to convert IPv4 mapped IPv6 address for dual-stack mode.
    if let SocketAddr::V6(ref a) = daddr {
        if let Some(v4) = to_ipv4_mapped(a.ip()) {
            daddr = SocketAddr::new(IpAddr::from(v4), a.port());
        }
    }
    let target_addr = Address::from(daddr);
    establish_client_tcp_redir(context, balancer, s, peer_addr, &target_addr).await
}

#[derive(Debug, Eq, PartialEq)]
enum TcpState {
    Established,
    FinWait,
    LastAck,
}

struct TcpConnection {
    saddr: SocketAddr,
    daddr: SocketAddr,
    faked_saddr: SocketAddr,
    state: TcpState,
}
