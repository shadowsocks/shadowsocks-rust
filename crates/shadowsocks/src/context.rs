//! Shadowsocks service context

use std::{io, net::SocketAddr, sync::Arc};

use byte_string::ByteStr;
use log::warn;

use crate::{
    config::{ReplayAttackPolicy, ServerType},
    crypto::{v1::random_iv_or_salt, CipherKind},
    dns_resolver::DnsResolver,
    security::replay::ReplayProtector,
};

/// Service context
pub struct Context {
    // Protector against replay attack
    // The actual replay detection behavior is implemented in ReplayProtector
    replay_protector: ReplayProtector,
    // Policy against replay attack
    replay_policy: ReplayAttackPolicy,

    // trust-dns resolver, which supports REAL asynchronous resolving, and also customizable
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

        loop {
            random_iv_or_salt(nonce);

            // SECURITY: First 6 bytes of payload should be printable characters
            // Observation shows that prepending 6 bytes of printable characters to random payload will exempt it from blocking.
            // by 2022-01-13 gfw.report et al.
            #[cfg(feature = "security-iv-printable-prefix")]
            {
                const SECURITY_PRINTABLE_PREFIX_LEN: usize = 6;
                if nonce.len() >= SECURITY_PRINTABLE_PREFIX_LEN {
                    // Printable characters use base64 letters instead
                    static ASCII_PRINTABLE_CHARS: &[u8] = br##"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"##;

                    for b in nonce.iter_mut().take(SECURITY_PRINTABLE_PREFIX_LEN) {
                        *b = ASCII_PRINTABLE_CHARS[(*b as usize) % ASCII_PRINTABLE_CHARS.len()];
                    }
                }
            }

            // Salt already exists, generate a new one.
            if unique && self.check_nonce_and_set(method, nonce) {
                continue;
            }

            break;
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
    #[allow(clippy::needless_lifetimes)]
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

    /// Get policy against replay attach
    pub fn replay_attack_policy(&self) -> ReplayAttackPolicy {
        self.replay_policy
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ServerType;
    use crate::context::Context;
    use byte_string::ByteStr;
    use shadowsocks_crypto::CipherKind;

    #[test]
    fn generate_nonce() {
        let mut salt = vec![0u8; 64];
        let context = Context::new(ServerType::Server);
        context.generate_nonce(CipherKind::AES_128_GCM, &mut salt, false);
        println!("generate nonce printable ascii: {:?}", ByteStr::new(&salt));
    }

}
