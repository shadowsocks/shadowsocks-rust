//! DNS Client cache

#[cfg(unix)]
use std::path::Path;
use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    future::Future,
    io,
    net::SocketAddr,
    time::Duration,
};

use hickory_resolver::proto::{ProtoError, op::Message};
use log::{debug, trace};
use tokio::sync::Mutex;

use shadowsocks::{config::ServerConfig, net::ConnectOpts, relay::socks5::Address};

use crate::local::context::ServiceContext;

use super::upstream::DnsClient;

#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
enum DnsClientKey {
    TcpLocal(SocketAddr),
    UdpLocal(SocketAddr),
    TcpRemote(Address),
    UdpRemote(Address),
}

pub struct DnsClientCache {
    cache: Mutex<HashMap<DnsClientKey, VecDeque<DnsClient>>>,
    timeout: Duration,
    retry_count: usize,
    max_client_per_addr: usize,
}

impl DnsClientCache {
    pub fn new(max_client_per_addr: usize) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(5),
            retry_count: 1,
            max_client_per_addr,
        }
    }

    pub async fn lookup_local(
        &self,
        ns: SocketAddr,
        msg: Message,
        connect_opts: &ConnectOpts,
        is_udp: bool,
    ) -> Result<Message, ProtoError> {
        let key = match is_udp {
            true => DnsClientKey::UdpLocal(ns),
            false => DnsClientKey::TcpLocal(ns),
        };
        self.lookup_dns(&key, msg, Some(connect_opts), None, None).await
    }

    pub async fn lookup_remote(
        &self,
        context: &ServiceContext,
        svr_cfg: &ServerConfig,
        ns: &Address,
        msg: Message,
        is_udp: bool,
    ) -> Result<Message, ProtoError> {
        let key = match is_udp {
            true => DnsClientKey::UdpRemote(ns.clone()),
            false => DnsClientKey::TcpRemote(ns.clone()),
        };
        self.lookup_dns(&key, msg, None, Some(context), Some(svr_cfg)).await
    }

    #[cfg(unix)]
    pub async fn lookup_unix_stream<P: AsRef<Path>>(&self, ns: &P, msg: Message) -> Result<Message, ProtoError> {
        let mut last_err = None;

        for _ in 0..self.retry_count {
            // UNIX stream won't keep connection alive
            //
            // https://github.com/shadowsocks/shadowsocks-rust/pull/567
            //
            // 1. The cost of recreating UNIX stream sockets are very low
            // 2. This feature is only used by shadowsocks-android, and it doesn't support connection reuse

            let mut client = match DnsClient::connect_unix_stream(ns).await {
                Ok(client) => client,
                Err(err) => {
                    last_err = Some(From::from(err));
                    continue;
                }
            };

            let res = match client.lookup_timeout(msg.clone(), self.timeout).await {
                Ok(msg) => msg,
                Err(error) => {
                    last_err = Some(error);
                    continue;
                }
            };
            return Ok(res);
        }
        Err(last_err.unwrap())
    }

    async fn lookup_dns(
        &self,
        dck: &DnsClientKey,
        msg: Message,
        connect_opts: Option<&ConnectOpts>,
        context: Option<&ServiceContext>,
        svr_cfg: Option<&ServerConfig>,
    ) -> Result<Message, ProtoError> {
        let mut last_err = None;
        for _ in 0..self.retry_count {
            let create_fn = async {
                match dck {
                    DnsClientKey::TcpLocal(tcp_l) => {
                        let connect_opts = connect_opts.expect("connect options is required for local DNS");
                        DnsClient::connect_tcp_local(*tcp_l, connect_opts).await
                    }
                    DnsClientKey::UdpLocal(udp_l) => {
                        let connect_opts = connect_opts.expect("connect options is required for local DNS");
                        DnsClient::connect_udp_local(*udp_l, connect_opts).await
                    }
                    DnsClientKey::TcpRemote(tcp_l) => {
                        let context = context.expect("context is required for remote DNS");
                        let svr_cfg = svr_cfg.expect("server config is required for remote DNS");

                        DnsClient::connect_tcp_remote(
                            context.context(),
                            svr_cfg,
                            tcp_l,
                            context.connect_opts_ref(),
                            context.flow_stat(),
                        )
                        .await
                    }
                    DnsClientKey::UdpRemote(udp_l) => {
                        let context = context.expect("context is required for remote DNS");
                        let svr_cfg = svr_cfg.expect("server config is required for remote DNS");

                        DnsClient::connect_udp_remote(
                            context.context(),
                            svr_cfg,
                            udp_l.clone(),
                            context.connect_opts_ref(),
                            context.flow_stat(),
                        )
                        .await
                    }
                }
            };
            match self.get_client_or_create(dck, create_fn).await {
                Ok(mut client) => match client.lookup_timeout(msg.clone(), self.timeout).await {
                    Ok(msg) => {
                        self.save_client(dck.clone(), client).await;
                        return Ok(msg);
                    }
                    Err(err) => {
                        last_err = Some(err);
                        continue;
                    }
                },
                Err(err) => {
                    last_err = Some(From::from(err));
                    continue;
                }
            }
        }
        Err(last_err.unwrap())
    }

    async fn get_client_or_create<C>(&self, key: &DnsClientKey, create_fn: C) -> io::Result<DnsClient>
    where
        C: Future<Output = io::Result<DnsClient>>,
    {
        // Check if there already is a cached client
        if let Some(q) = self.cache.lock().await.get_mut(key) {
            while let Some(mut c) = q.pop_front() {
                trace!("take cached DNS client for {:?}", key);
                if !c.check_connected().await {
                    debug!("cached DNS client for {:?} is lost", key);
                    continue;
                }
                return Ok(c);
            }
        }
        trace!("creating connection to DNS server {:?}", key);

        // Create one
        create_fn.await
    }

    async fn save_client(&self, key: DnsClientKey, client: DnsClient) {
        match self.cache.lock().await.entry(key) {
            Entry::Occupied(occ) => {
                let q = occ.into_mut();
                q.push_back(client);
                if q.len() > self.max_client_per_addr {
                    q.pop_front();
                }
            }
            Entry::Vacant(vac) => {
                let mut q = VecDeque::with_capacity(self.max_client_per_addr);
                q.push_back(client);
                vac.insert(q);
            }
        }
    }
}
