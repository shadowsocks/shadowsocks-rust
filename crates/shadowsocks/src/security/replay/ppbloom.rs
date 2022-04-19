#[cfg(feature = "aead-cipher-2022")]
use std::time::Duration;

use bloomfilter::Bloom;
use log::debug;
#[cfg(feature = "aead-cipher-2022")]
use lru_time_cache::LruCache;
use spin::Mutex as SpinMutex;

#[cfg(feature = "aead-cipher-2022")]
use crate::relay::tcprelay::proxy_stream::protocol::v2::SERVER_STREAM_TIMESTAMP_MAX_DIFF;
use crate::{config::ServerType, crypto::CipherKind};

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
    pub fn new(ty: ServerType) -> PingPongBloom {
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
    pub fn check_and_set(&mut self, buf: &[u8]) -> bool {
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

            debug!(
                "bloom filter based replay protector full, each capacity: {}, total filters: {}",
                self.item_count,
                self.blooms.len(),
            );
        }

        // Cannot be optimized by `check_and_set`
        // Because we have to check every filters in `blooms` before `set`
        self.blooms[self.current].set(buf);
        self.bloom_count[self.current] += 1;

        false
    }
}

/// A Bloom Filter based protector against replay attach
pub struct ReplayProtector {
    // Check for duplicated IV/Nonce, for prevent replay attack
    // https://github.com/shadowsocks/shadowsocks-org/issues/44
    nonce_ppbloom: SpinMutex<PingPongBloom>,

    // AEAD 2022 specific filter.
    // AEAD 2022 TCP protocol has a timestamp, which can already reject most of the replay requests,
    // so we only need to remember nonce that are in the valid time range
    #[cfg(feature = "aead-cipher-2022")]
    nonce_set: SpinMutex<LruCache<Vec<u8>, ()>>,
}

impl ReplayProtector {
    /// Create a new ReplayProtector
    pub fn new(config_type: ServerType) -> ReplayProtector {
        ReplayProtector {
            nonce_ppbloom: SpinMutex::new(PingPongBloom::new(config_type)),
            #[cfg(feature = "aead-cipher-2022")]
            nonce_set: SpinMutex::new(LruCache::with_expiry_duration(Duration::from_secs(
                SERVER_STREAM_TIMESTAMP_MAX_DIFF,
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

        let mut ppbloom = self.nonce_ppbloom.lock();
        ppbloom.check_and_set(nonce)
    }
}
