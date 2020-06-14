//! Shadowsocks Server Context

#[cfg(feature = "local-dns-relay")]
use std::net::IpAddr;
#[cfg(any(feature = "local-dns-relay", feature = "acl-check-cache"))]
use std::time::Duration;
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use bloomfilter::Bloom;
#[cfg(feature = "acl-check-cache")]
use log::trace;
use log::{log_enabled, warn};
#[cfg(any(feature = "local-dns-relay", feature = "acl-check-cache"))]
use lru_time_cache::LruCache;
use spin::Mutex as SpinMutex;
#[cfg(feature = "acl-check-cache")]
use tokio::sync::Mutex as AsyncMutex;
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::TokioAsyncResolver;

#[cfg(any(feature = "sodium", feature = "rc4"))]
use crate::crypto::CipherType;
#[cfg(feature = "trust-dns")]
use crate::relay::dns_resolver::create_resolver;
#[cfg(not(feature = "local-dns-relay"))]
use crate::relay::dns_resolver::resolve;
#[cfg(feature = "local-dns-relay")]
use crate::relay::dnsrelay::upstream::LocalUpstream;
#[cfg(feature = "local-flow-stat")]
use crate::relay::flow::ServerFlowStatistic;
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
    pub async fn new_shared(config: &Config) -> SharedServerState {
        let state = ServerState {
            dns_resolver: match create_resolver(config.get_dns_config(), config.ipv6_first).await {
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
    pub async fn new_shared(_config: &Config) -> SharedServerState {
        Arc::new(ServerState {})
    }
}

/// `ServerState` wrapped in `Arc`
pub type SharedServerState = Arc<ServerState>;

/// ACL check result cache
#[cfg(feature = "acl-check-cache")]
struct AclCheckCache {
    target_cache: AsyncMutex<LruCache<Address, bool>>,
    outbound_cache: AsyncMutex<LruCache<Address, bool>>,
    client_cache: AsyncMutex<LruCache<SocketAddr, bool>>,
}

#[cfg(feature = "acl-check-cache")]
impl AclCheckCache {
    /// Create a cache with default configuration
    fn new() -> AclCheckCache {
        const TARGET_CACHE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
        const TARGET_CACHE_COUNT: usize = 256;

        const OUTBOUND_CACHE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
        const OUTBOUND_CACHE_COUNT: usize = 1024;

        const CLIENT_CACHE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
        const CLIENT_CACHE_COUNT: usize = 1024;

        AclCheckCache {
            target_cache: AsyncMutex::new(LruCache::with_expiry_duration_and_capacity(
                TARGET_CACHE_DURATION,
                TARGET_CACHE_COUNT,
            )),
            outbound_cache: AsyncMutex::new(LruCache::with_expiry_duration_and_capacity(
                OUTBOUND_CACHE_DURATION,
                OUTBOUND_CACHE_COUNT,
            )),
            client_cache: AsyncMutex::new(LruCache::with_expiry_duration_and_capacity(
                CLIENT_CACHE_DURATION,
                CLIENT_CACHE_COUNT,
            )),
        }
    }

    /// Check target bypassed in cache
    async fn check_target_bypassed(&self, target: &Address) -> Option<bool> {
        self.target_cache.lock().await.get(target).map(|x| *x)
    }

    /// Update target bypassed into cache
    async fn update_target_bypassed(&self, target: Address, bypassed: bool) -> bool {
        self.target_cache.lock().await.insert(target, bypassed);
        bypassed
    }

    /// Check client blocked in cache
    async fn check_client_blocked(&self, client: &SocketAddr) -> Option<bool> {
        self.client_cache.lock().await.get(client).map(|x| *x)
    }

    /// Update client blocked in cache
    async fn update_client_blocked(&self, client: SocketAddr, blocked: bool) -> bool {
        self.client_cache.lock().await.insert(client, blocked);
        blocked
    }

    /// Check outbound blocked in cache
    async fn check_outbound_blocked(&self, outbound: &Address) -> Option<bool> {
        self.outbound_cache.lock().await.get(outbound).map(|x| *x)
    }

    /// Update outbound blocked in cache
    async fn update_outbound_blocked(&self, outbound: Address, blocked: bool) -> bool {
        self.outbound_cache.lock().await.insert(outbound, blocked);
        blocked
    }
}

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
    nonce_ppbloom: SpinMutex<PingPongBloom>,

    // For Android's flow stat report
    #[cfg(feature = "local-flow-stat")]
    local_flow_statistic: ServerFlowStatistic,

    // For DNS relay's ACL domain name reverse lookup -- whether the IP shall be forwarded
    #[cfg(feature = "local-dns-relay")]
    reverse_lookup_cache: AsyncMutex<LruCache<IpAddr, bool>>,

    // For local DNS upstream
    #[cfg(feature = "local-dns-relay")]
    local_dns: LocalUpstream,

    // ACL check result cache
    #[cfg(feature = "acl-check-cache")]
    acl_check_cache: AclCheckCache,
}

/// Unique context thw whole server
pub type SharedContext = Arc<Context>;

impl Context {
    /// Create a non-shared Context
    async fn new(config: Config) -> Context {
        let state = ServerState::new_shared(&config).await;
        Context::new_with_state(config, state)
    }

    /// Create a non-shared Context with a `ServerState`
    ///
    /// This is useful when you are running multiple servers in one process
    fn new_with_state(config: Config, server_state: SharedServerState) -> Context {
        for server in &config.server {
            let t = server.method();

            // Warning for deprecated ciphers
            // The following stream ciphers have inherent weaknesses (see discussion at https://github.com/shadowsocks/shadowsocks-org/issues/36).
            // DO NOT USE. Implementors are advised to remove them as soon as possible.
            let deprecated = match t {
                #[cfg(feature = "sodium")]
                CipherType::ChaCha20 | CipherType::Salsa20 => true,
                #[cfg(feature = "rc4")]
                CipherType::Rc4Md5 => true,
                _ => false,
            };
            if deprecated {
                warn!(
                    "stream cipher {} (for server {}) have inherent weaknesses \
                       (see discussion at https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                       DO NOT USE. It will be removed in the future.",
                    t,
                    server.addr(),
                );
            }
        }

        let nonce_ppbloom = SpinMutex::new(PingPongBloom::new(config.config_type));
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
            reverse_lookup_cache: AsyncMutex::new(LruCache::with_expiry_duration(Duration::from_secs(
                3 * 24 * 60 * 60,
            ))),
            #[cfg(feature = "local-dns-relay")]
            local_dns,
            #[cfg(feature = "acl-check-cache")]
            acl_check_cache: AclCheckCache::new(),
        }
    }

    /// Create a shared `Context`, wrapped in `Arc`
    pub async fn new_shared(config: Config) -> SharedContext {
        SharedContext::new(Context::new(config).await)
    }

    /// Create a shared `Context`, wrapped in `Arc` with a `ServerState`
    ///
    /// This is useful when you are running multiple servers in one process
    pub fn new_with_state_shared(config: Config, server_state: SharedServerState) -> SharedContext {
        SharedContext::new(Context::new_with_state(config, server_state))
    }

    /// Config for TCP server
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// ServerState
    pub fn server_state(&self) -> &SharedServerState {
        &self.server_state
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
        if log_enabled!(log::Level::Debug) {
            use log::debug;
            use std::time::Instant;

            let start = Instant::now();
            let result = self.dns_resolve_impl(host, port).await;
            let elapsed = Instant::now() - start;
            debug!(
                "DNS resolved {}:{} elapsed: {}.{:03}s, {:?}",
                host,
                port,
                elapsed.as_secs(),
                elapsed.subsec_millis(),
                result
            );
            result
        } else {
            self.dns_resolve_impl(host, port).await
        }
    }

    #[cfg(feature = "local-dns-relay")]
    #[inline(always)]
    async fn dns_resolve_impl(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.local_dns().lookup_ip(host, port).await
    }

    #[cfg(not(feature = "local-dns-relay"))]
    #[inline(always)]
    async fn dns_resolve_impl(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
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
    #[cfg(not(feature = "acl-check-cache"))]
    pub async fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        match self.acl() {
            None => false,
            Some(a) => a.check_client_blocked(addr),
        }
    }

    /// Check client ACL (for server)
    #[cfg(feature = "acl-check-cache")]
    pub async fn check_client_blocked(&self, addr: &SocketAddr) -> bool {
        match self.acl() {
            None => false,
            Some(a) => {
                if let Some(r) = self.acl_check_cache.check_client_blocked(addr).await {
                    trace!(
                        "check client {} cached result: {}",
                        addr,
                        if r { "blocked" } else { "passed" }
                    );

                    return r;
                }

                let r = a.check_client_blocked(addr);
                self.acl_check_cache.update_client_blocked(addr.clone(), r).await
            }
        }
    }

    /// Check outbound address ACL (for server)
    #[cfg(not(feature = "acl-check-cache"))]
    pub async fn check_outbound_blocked(&self, addr: &Address) -> bool {
        match self.acl() {
            None => false,
            Some(a) => a.check_outbound_blocked(self, addr).await,
        }
    }

    /// Check outbound address ACL (for server)
    #[cfg(feature = "acl-check-cache")]
    pub async fn check_outbound_blocked(&self, addr: &Address) -> bool {
        match self.acl() {
            None => false,
            Some(a) => {
                if let Some(r) = self.acl_check_cache.check_outbound_blocked(addr).await {
                    trace!(
                        "check outbound {} cached result: {}",
                        addr,
                        if r { "blocked" } else { "passed" }
                    );

                    return r;
                }

                let r = a.check_outbound_blocked(self, addr).await;
                self.acl_check_cache.update_outbound_blocked(addr.clone(), r).await
            }
        }
    }

    /// Add a record to the reverse lookup cache
    #[cfg(feature = "local-dns-relay")]
    pub async fn add_to_reverse_lookup_cache(&self, addr: &IpAddr, forward: bool) {
        let is_exception = forward
            != match self.acl() {
                // Proxy everything by default
                None => true,
                Some(a) => a.check_ip_in_proxy_list(addr),
            };
        let mut reverse_lookup_cache = self.reverse_lookup_cache.lock().await;
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

    /// Get ACL control instance
    pub fn acl(&self) -> Option<&AccessControl> {
        self.config.acl.as_ref()
    }

    /// Get local DNS connector
    #[cfg(feature = "local-dns-relay")]
    pub fn local_dns(&self) -> &LocalUpstream {
        &self.local_dns
    }

    /// Check target address ACL (for client)
    pub async fn check_target_bypassed(&self, target: &Address) -> bool {
        match self.acl() {
            // Proxy everything by default
            None => false,
            Some(a) => {
                #[cfg(feature = "local-dns-relay")]
                {
                    if let Address::SocketAddress(ref saddr) = target {
                        // do the reverse lookup in our local cache
                        let mut reverse_lookup_cache = self.reverse_lookup_cache.lock().await;
                        // if a qname is found
                        if let Some(forward) = reverse_lookup_cache.get(&saddr.ip()) {
                            return !*forward;
                        }
                    }
                }

                self.check_target_bypassed_with_acl(a, target).await
            }
        }
    }

    #[inline(always)]
    #[cfg(feature = "acl-check-cache")]
    async fn check_target_bypassed_with_acl(&self, a: &AccessControl, target: &Address) -> bool {
        // ACL checking may need over 500ms (DNS resolving)
        if let Some(bypassed) = self.acl_check_cache.check_target_bypassed(target).await {
            trace!(
                "check bypassing {} cached result: {}",
                target,
                if bypassed { "bypassed" } else { "proxied" }
            );

            return bypassed;
        }

        let r = a.check_target_bypassed(self, target).await;
        self.acl_check_cache.update_target_bypassed(target.clone(), r).await
    }

    #[inline(always)]
    #[cfg(not(feature = "acl-check-cache"))]
    async fn check_target_bypassed_with_acl(&self, a: &AccessControl, target: &Address) -> bool {
        a.check_target_bypassed(self, target).await
    }

    /// Get client flow statistics
    #[cfg(feature = "local-flow-stat")]
    pub fn local_flow_statistic(&self) -> &ServerFlowStatistic {
        &self.local_flow_statistic
    }
}
