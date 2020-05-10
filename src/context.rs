//! Shadowsocks Server Context

use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[cfg(feature = "local-dns-relay")]
use std::{net::IpAddr, time::Duration};

use bloomfilter::Bloom;
#[cfg(feature = "local-dns-relay")]
use lru_time_cache::LruCache;
use spin::Mutex;
use tokio::runtime::Handle;
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::TokioAsyncResolver;

#[cfg(feature = "trust-dns")]
use crate::relay::dns_resolver::create_resolver;
#[cfg(feature = "local-flow-stat")]
use crate::relay::flow::ServerFlowStatistic;
#[cfg(feature = "local-dns-relay")]
use crate::relay::dnsrelay::upstream::LocalUpstream;
#[cfg(not(feature = "local-dns-relay"))]
use crate::relay::dns_resolver::resolve;
use crate::{
    acl::AccessControl,
    config::{Config, ConfigType, ServerConfig},
    relay::socks5::Address,
};

// Entries for server's bloom filter
//
// Borrowed from shadowsocks-libev's default value
const BF_NUM_ENTRIES_FOR_SERVER: usize = 1_000_000;

// Entries for client's bloom filter
//
// Borrowed from shadowsocks-libev's default value
const BF_NUM_ENTRIES_FOR_CLIENT: usize = 10_000;

// Error rate for server's bloom filter
//
// Borrowed from shadowsocks-libev's default value
const BF_ERROR_RATE_FOR_SERVER: f64 = 1e-6;

// Error rate for client's bloom filter
//
// Borrowed from shadowsocks-libev's default value
const BF_ERROR_RATE_FOR_CLIENT: f64 = 1e-15;

// A bloom filter borrowed from shadowsocks-libev's `ppbloom`
//
// It contains 2 bloom filters and each one holds 1/2 entries.
// Use them as a ring buffer.
struct PingPongBloom {
    blooms: [Bloom<[u8]>; 2],
    bloom_count: [usize; 2],
    item_count: usize,
    current: usize,
}

impl PingPongBloom {
    fn new(ty: ConfigType) -> PingPongBloom {
        let (mut item_count, fp_p) = if ty.is_local() {
            (BF_NUM_ENTRIES_FOR_CLIENT, BF_ERROR_RATE_FOR_CLIENT)
        } else {
            (BF_NUM_ENTRIES_FOR_SERVER, BF_ERROR_RATE_FOR_SERVER)
        };

        item_count /= 2;

        PingPongBloom {
            blooms: [
                Bloom::new_for_fp_rate(item_count, fp_p),
                Bloom::new_for_fp_rate(item_count, fp_p),
            ],
            bloom_count: [0, 0],
            item_count,
            current: 0,
        }
    }

    // Check if data in `buf` exist.
    //
    // Set into the current bloom filter if not exist.
    //
    // Return `true` if data exist in bloom filter.
    fn check_and_set(&mut self, buf: &[u8]) -> bool {
        for bloom in &self.blooms {
            if bloom.check(buf) {
                return true;
            }
        }

        if self.bloom_count[self.current] >= self.item_count {
            // Current bloom filter is full,
            // Create a new one and use that one as current.

            self.current = (self.current + 1) % 2;

            self.bloom_count[self.current] = 0;
            self.blooms[self.current].clear();
        }

        // Cannot be optimized by `check_and_set`
        // Because we have to check every filters in `blooms` before `set`
        self.blooms[self.current].set(buf);
        self.bloom_count[self.current] += 1;

        false
    }
}

/// Server's global running status
///
/// Shared between UDP and TCP servers
pub struct ServerState {
    #[cfg(feature = "trust-dns")]
    dns_resolver: Option<TokioAsyncResolver>,
}

#[cfg(feature = "trust-dns")]
impl ServerState {
    /// Create a global shared server state
    pub async fn new_shared(config: &Config, rt: Handle) -> SharedServerState {
        let state = ServerState {
            dns_resolver: match create_resolver(config.get_dns_config(), config.timeout, config.ipv6_first, rt).await {
                Ok(resolver) => Some(resolver),
                Err(..) => None,
            },
        };

        Arc::new(state)
    }

    /// Get the global shared resolver
    pub fn dns_resolver(&self) -> Option<&TokioAsyncResolver> {
        self.dns_resolver.as_ref()
    }
}

#[cfg(not(feature = "trust-dns"))]
impl ServerState {
    /// Create a global shared server state
    pub async fn new_shared(_config: &Config, _rt: Handle) -> SharedServerState {
        Arc::new(ServerState {})
    }
}

/// `ServerState` wrapped in `Arc`
pub type SharedServerState = Arc<ServerState>;

/// Shared basic configuration for the whole server
pub struct Context {
    config: Config,

    // Shared variables for all servers
    server_state: SharedServerState,

    // Server's running indicator
    // For killing all background jobs
    server_running: AtomicBool,

    // Check for duplicated IV/Nonce, for prevent replay attack
    // https://github.com/shadowsocks/shadowsocks-org/issues/44
    nonce_ppbloom: Mutex<PingPongBloom>,

    // For Android's flow stat report
    #[cfg(feature = "local-flow-stat")]
    local_flow_statistic: ServerFlowStatistic,

    // For DNS relay's ACL domain name reverse lookup -- whether the IP shall be forwarded
    #[cfg(feature = "local-dns-relay")]
    reverse_lookup_cache: Mutex<LruCache<IpAddr, bool>>,

    // For local DNS upstream
    #[cfg(feature = "local-dns-relay")]
    local_dns: LocalUpstream,
}

/// Unique context thw whole server
pub type SharedContext = Arc<Context>;

impl Context {
    /// Create a non-shared Context
    fn new(config: Config, server_state: SharedServerState) -> Context {
        let nonce_ppbloom = Mutex::new(PingPongBloom::new(config.config_type));
        #[cfg(feature = "local-dns-relay")]
        let reverse_lookup_cache = Mutex::new(LruCache::<IpAddr, bool>::with_expiry_duration(Duration::from_secs(
            3 * 24 * 60 * 60,
        )));
        #[cfg(feature = "local-dns-relay")]
        let local_dns = LocalUpstream::new(&config);

        Context {
            config,
            server_state,
            server_running: AtomicBool::new(true),
            nonce_ppbloom,
            #[cfg(feature = "local-flow-stat")]
            local_flow_statistic: ServerFlowStatistic::new(),
            #[cfg(feature = "local-dns-relay")]
            reverse_lookup_cache,
            #[cfg(feature = "local-dns-relay")]
            local_dns,
        }
    }

    /// Create a shared Context, wrapped in `Arc`
    pub fn new_shared(config: Config, server_state: SharedServerState) -> SharedContext {
        SharedContext::new(Context::new(config, server_state))
    }

    /// Config for TCP server
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Clone the internal ServerState
    pub fn clone_server_state(&self) -> SharedServerState {
        self.server_state.clone()
    }

    /// Mutable Config for TCP server
    ///
    /// NOTE: Only for launching plugins
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Get ServerConfig by index
    pub fn server_config(&self, idx: usize) -> &ServerConfig {
        &self.config.server[idx]
    }

    /// Get mutable ServerConfig by index
    pub fn server_config_mut(&mut self, idx: usize) -> &mut ServerConfig {
        &mut self.config.server[idx]
    }

    #[cfg(feature = "trust-dns")]
    /// Get the global shared resolver
    pub fn dns_resolver(&self) -> Option<&TokioAsyncResolver> {
        self.server_state.dns_resolver()
    }

    /// Perform a DNS resolution
    pub async fn dns_resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        #[cfg(feature = "local-dns-relay")]
        return self.local_dns().lookup_ip(host, port).await;
        #[cfg(not(feature = "local-dns-relay"))]
        resolve(self, host, port).await
    }

    /// Check if the server is still in running state
    pub fn server_running(&self) -> bool {
        self.server_running.load(Ordering::Acquire)
    }

    /// Stops the server, kills all detached running tasks
    pub fn set_server_stopped(&self) {
        self.server_running.store(false, Ordering::Release)
    }

    /// Check if nonce exist or not
    ///
    /// If not, set into the current bloom filter
    pub fn check_nonce_and_set(&self, nonce: &[u8]) -> bool {
        // Plain cipher doesn't have a nonce
        // Always treated as non-duplicated
        if nonce.is_empty() {
            return false;
        }

        let mut ppbloom = self.nonce_ppbloom.lock();
        ppbloom.check_and_set(nonce)
    }

    /// Check client ACL (for server)
    pub fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        match self.acl() {
            None => false,
            Some(ref a) => a.check_client_blocked(addr),
        }
    }

    /// Check outbound address ACL (for server)
    pub fn check_outbound_blocked(&self, addr: &Address) -> bool {
        match self.acl() {
            None => false,
            Some(ref a) => a.check_outbound_blocked(addr),
        }
    }

    /// Check resolved outbound address ACL (for server)
    pub fn check_resolved_outbound_blocked(&self, addr: &SocketAddr) -> bool {
        match self.acl() {
            None => false,
            Some(ref a) => a.check_resolved_outbound_blocked(addr),
        }
    }

    /// Add a record to the reverse lookup cache
    #[cfg(feature = "local-dns-relay")]
    pub fn add_to_reverse_lookup_cache(&self, addr: &IpAddr, forward: bool) {
        let is_exception = forward != match self.acl() {
            // Proxy everything by default
            None => true,
            Some(ref a) => a.check_ip_in_proxy_list(addr)
        };
        let mut reverse_lookup_cache = self.reverse_lookup_cache.lock();
        match reverse_lookup_cache.get_mut(addr) {
            Some(value) => {
                if is_exception {
                    *value = forward;
                } else {
                    // we do not need to remember the entry if it is already matched correctly
                    reverse_lookup_cache.remove(addr);
                }
            }
            None => {
                if is_exception {
                    reverse_lookup_cache.insert(addr.clone(), forward);
                }
            }
        }
    }

    pub fn acl(&self) -> &Option<AccessControl> {
        &self.config.acl
    }

    pub fn local_dns(&self) -> &LocalUpstream {
        &self.local_dns
    }

    /// Check target address ACL (for client)
    pub async fn check_target_bypassed(&self, target: &Address) -> bool {
        match self.acl() {
            // Proxy everything by default
            None => false,
            Some(ref a) => {
                #[cfg(feature = "local-dns-relay")]
                {
                    if let Address::SocketAddress(ref saddr) = target {
                        // do the reverse lookup in our local cache
                        let mut reverse_lookup_cache = self.reverse_lookup_cache.lock();
                        // if a qname is found
                        if let Some(forward) = reverse_lookup_cache.get(&saddr.ip()) {
                            return !*forward;
                        }
                    }
                }
                a.check_target_bypassed(self, target).await
            }
        }
    }

    /// Get client flow statistics
    #[cfg(feature = "local-flow-stat")]
    pub fn local_flow_statistic(&self) -> &ServerFlowStatistic {
        &self.local_flow_statistic
    }
}
