use std::fmt;

#[cfg(feature = "aead-cipher-2022")]
use std::time::Duration;

use cfg_if::cfg_if;
#[cfg(feature = "aead-cipher-2022")]
use lru_time_cache::LruCache;

#[cfg(feature = "aead-cipher-2022")]
use crate::relay::tcprelay::proxy_stream::protocol::v2::SERVER_STREAM_TIMESTAMP_MAX_DIFF;
use crate::{config::ServerType, crypto::CipherKind};

#[cfg(feature = "security-replay-attack-detect")]
use self::ppbloom::PingPongBloom;

#[cfg(feature = "security-replay-attack-detect")]
mod ppbloom;

/// A Bloom Filter based protector against replay attack
pub struct ReplayProtector {
    // Check for duplicated IV/Nonce, for prevent replay attack
    // https://github.com/shadowsocks/shadowsocks-org/issues/44
    #[cfg(feature = "security-replay-attack-detect")]
    nonce_ppbloom: spin::Mutex<PingPongBloom>,

    // AEAD 2022 specific filter.
    // AEAD 2022 TCP protocol has a timestamp, which can already reject most of the replay requests,
    // so we only need to remember nonce that are in the valid time range
    #[cfg(feature = "aead-cipher-2022")]
    nonce_set: spin::Mutex<LruCache<Vec<u8>, ()>>,
}

impl fmt::Debug for ReplayProtector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ReplayProtector").finish()
    }
}

impl ReplayProtector {
    /// Create a new ReplayProtector
    #[allow(unused_variables)]
    pub fn new(config_type: ServerType) -> ReplayProtector {
        ReplayProtector {
            #[cfg(feature = "security-replay-attack-detect")]
            nonce_ppbloom: spin::Mutex::new(PingPongBloom::new(config_type)),
            #[cfg(feature = "aead-cipher-2022")]
            nonce_set: spin::Mutex::new(LruCache::with_expiry_duration(Duration::from_secs(
                SERVER_STREAM_TIMESTAMP_MAX_DIFF * 2,
            ))),
        }
    }

    /// Check if nonce exist or not
    #[inline(always)]
    pub fn check_nonce_and_set(&self, method: CipherKind, nonce: &[u8]) -> bool {
        // Plain cipher doesn't have a nonce
        // Always treated as non-duplicated
        if nonce.is_empty() {
            return false;
        }

        #[cfg(feature = "aead-cipher-2022")]
        if method.is_aead_2022() {
            let mut set = self.nonce_set.lock();
            if set.get(nonce).is_some() {
                return true;
            }
            set.insert(nonce.to_vec(), ());
            return false;
        }

        let _ = method;

        cfg_if! {
            if #[cfg(feature = "security-replay-attack-detect")] {
                let mut ppbloom = self.nonce_ppbloom.lock();
                ppbloom.check_and_set(nonce)
            } else {
                false
            }
        }
    }
}
