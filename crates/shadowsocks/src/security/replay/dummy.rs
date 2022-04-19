use crate::{config::ServerType, crypto::CipherKind};

/// A dummy protector against replay attack
///
/// It is dummy because it can protect nothing.
pub struct ReplayProtector;

impl ReplayProtector {
    /// Create a new ReplayProtector
    #[inline(always)]
    pub fn new(_: ServerType) -> ReplayProtector {
        ReplayProtector
    }

    /// Check if nonce exist or not
    #[inline(always)]
    pub fn check_nonce_and_set(&self, _method: CipherKind, _nonce: &[u8]) -> bool {
        false
    }
}
