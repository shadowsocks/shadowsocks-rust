//! Shadowsocks Server Context

use std::{
    io,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use bloomfilter::Bloom;
use spin::Mutex;
use tokio::runtime::Handle;
#[cfg(feature = "trust-dns")]
use trust_dns_resolver::TokioAsyncResolver;

use crate::config::{Config, ConfigType, ServerConfig};
#[cfg(feature = "trust-dns")]
use crate::relay::dns_resolver::create_resolver;

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
    dns_resolver: TokioAsyncResolver,
}

impl ServerState {
    #[allow(unused_variables)]
    pub async fn new_shared(config: &Config, rt: Handle) -> io::Result<SharedServerState> {
        let state = ServerState {
            #[cfg(feature = "trust-dns")]
            dns_resolver: create_resolver(config.get_dns_config(), rt).await?,
        };

        Ok(Arc::new(state))
    }

    /// Get the global shared resolver
    #[cfg(feature = "trust-dns")]
    pub fn dns_resolver(&self) -> &TokioAsyncResolver {
        &self.dns_resolver
    }
}

/// `ServerState` wrapped in `Arc`
pub type SharedServerState = Arc<ServerState>;

/// Shared basic configuration for the whole server
pub struct Context {
    config: Config,
    server_state: SharedServerState,
    server_running: AtomicBool,
    nonce_ppbloom: Mutex<PingPongBloom>,
}

/// Unique context thw whole server
pub type SharedContext = Arc<Context>;

impl Context {
    /// Create a non-shared Context
    fn new(config: Config, server_state: SharedServerState) -> Context {
        let nonce_ppbloom = Mutex::new(PingPongBloom::new(config.config_type));

        Context {
            config,
            server_state,
            server_running: AtomicBool::new(true),
            nonce_ppbloom,
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
    pub fn dns_resolver(&self) -> &TokioAsyncResolver {
        self.server_state.dns_resolver()
    }

    /// Check if the server is still in running state
    pub fn server_running(&self) -> bool {
        self.server_running.load(Ordering::Acquire)
    }

    /// Stops the server, kills all detached running tasks
    pub fn server_stopped(&self) {
        self.server_running.store(false, Ordering::Release)
    }

    /// Check if IP is in forbidden list
    pub fn check_forbidden_ip(&self, ip: &IpAddr) -> bool {
        self.config.check_forbidden_ip(ip)
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
}
