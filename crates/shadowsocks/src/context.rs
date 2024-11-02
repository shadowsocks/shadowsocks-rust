//! Shadowsocks service context

use std::{io, net::SocketAddr, sync::Arc};

use byte_string::ByteStr;
use log::warn;

use crate::{
    config::{ReplayAttackPolicy, ServerType},
    crypto::CipherKind,
    dns_resolver::DnsResolver,
    security::replay::ReplayProtector,
};

/// Service context
#[derive(Debug)]
pub struct Context {
    // Protector against replay attack
    // The actual replay detection behavior is implemented in ReplayProtector
    replay_protector: ReplayProtector,
    // Policy against replay attack
    replay_policy: ReplayAttackPolicy,

    // hickory-dns resolver, which supports REAL asynchronous resolving, and also customizable
    dns_resolver: Arc<DnsResolver>,

    // Connect IPv6 address first
    ipv6_first: bool,
}

/// `Context` for sharing between services
pub type SharedContext = Arc<Context>;

impl Context {
    /// Create a new `Context` for `Client` or `Server`
    pub fn new(config_type: ServerType) -> Context {
        Context {
            replay_protector: ReplayProtector::new(config_type),
            replay_policy: ReplayAttackPolicy::Default,
            dns_resolver: Arc::new(DnsResolver::system_resolver()),
            ipv6_first: false,
        }
    }

    /// Create a new `Context` shared
    pub fn new_shared(config_type: ServerType) -> SharedContext {
        SharedContext::new(Context::new(config_type))
    }

    /// Check if nonce exist or not
    ///
    /// If not, set into the current bloom filter
    #[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
    #[inline(always)]
    fn check_nonce_and_set(&self, method: CipherKind, nonce: &[u8]) -> bool {
        match self.replay_policy {
            ReplayAttackPolicy::Ignore => false,
            _ => self.replay_protector.check_nonce_and_set(method, nonce),
        }
    }

    /// Generate nonce (IV or SALT)
    pub fn generate_nonce(&self, method: CipherKind, nonce: &mut [u8], unique: bool) {
        if nonce.is_empty() {
            return;
        }

        #[cfg(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022"))]
        loop {
            use crate::crypto::utils::random_iv_or_salt;

            random_iv_or_salt(nonce);

            // Salt already exists, generate a new one.
            if unique && self.check_nonce_and_set(method, nonce) {
                continue;
            }

            break;
        }

        #[cfg(not(any(feature = "stream-cipher", feature = "aead-cipher", feature = "aead-cipher-2022")))]
        if !nonce.is_empty() {
            let _ = unique;
            panic!("{method} don't know how to generate nonce");
        }
    }

    /// Check nonce replay
    pub fn check_nonce_replay(&self, method: CipherKind, nonce: &[u8]) -> io::Result<()> {
        if nonce.is_empty() {
            return Ok(());
        }

        #[allow(unused_mut)]
        let mut replay_policy = self.replay_policy;

        #[cfg(feature = "aead-cipher-2022")]
        if method.is_aead_2022() {
            // AEAD-2022 can't be ignored.
            replay_policy = ReplayAttackPolicy::Reject;
        }

        match replay_policy {
            ReplayAttackPolicy::Default | ReplayAttackPolicy::Ignore => Ok(()),
            ReplayAttackPolicy::Detect => {
                if self.replay_protector.check_nonce_and_set(method, nonce) {
                    warn!("detected repeated nonce (iv/salt) {:?}", ByteStr::new(nonce));
                }
                Ok(())
            }
            ReplayAttackPolicy::Reject => {
                if self.replay_protector.check_nonce_and_set(method, nonce) {
                    let err = io::Error::new(io::ErrorKind::Other, "detected repeated nonce (iv/salt)");
                    Err(err)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Set a DNS resolver
    ///
    /// The resolver should be wrapped in an `Arc`, because it could be shared with the other servers
    pub fn set_dns_resolver(&mut self, resolver: Arc<DnsResolver>) {
        self.dns_resolver = resolver;
    }

    /// Get the DNS resolver
    pub fn dns_resolver(&self) -> &Arc<DnsResolver> {
        &self.dns_resolver
    }

    /// Resolves DNS address to `SocketAddr`s
    pub async fn dns_resolve<'a>(&self, addr: &'a str, port: u16) -> io::Result<impl Iterator<Item = SocketAddr> + 'a> {
        self.dns_resolver.resolve(addr, port).await
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn set_ipv6_first(&mut self, ipv6_first: bool) {
        self.ipv6_first = ipv6_first;
    }

    /// Try to connect IPv6 addresses first if hostname could be resolved to both IPv4 and IPv6
    pub fn ipv6_first(&self) -> bool {
        self.ipv6_first
    }

    /// Set policy against replay attack
    pub fn set_replay_attack_policy(&mut self, replay_policy: ReplayAttackPolicy) {
        self.replay_policy = replay_policy;
    }

    /// Get policy against replay attack
    pub fn replay_attack_policy(&self) -> ReplayAttackPolicy {
        self.replay_policy
    }
}
