//! Dummy cipher, encrypt and decrypt nothing

use super::{StreamCipher, CipherResult};

use bytes::BufMut;

/// Dummy cipher
///
/// Copies data directly to output, very dummy
pub struct DummyCipher;

impl StreamCipher for DummyCipher {
    fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        out.put_slice(data);
        Ok(())
    }

    fn finalize<B: BufMut>(&mut self, _: &mut B) -> CipherResult<()> {
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}
