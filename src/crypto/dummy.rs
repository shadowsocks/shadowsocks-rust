//! Dummy cipher, encrypt and decrypt nothing

use super::{StreamCipher, CipherResult};

/// Dummy cipher
///
/// Copies data directly to output, very dummy
pub struct DummyCipher;

impl StreamCipher for DummyCipher {
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        out.extend_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self, _: &mut Vec<u8>) -> CipherResult<()> {
        Ok(())
    }
}