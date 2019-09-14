//! Dummy cipher, encrypt and decrypt nothing

use super::{CipherResult, StreamCipher};

use bytes::BufMut;

/// Dummy cipher
///
/// Copies data directly to output, very dummy
pub struct DummyCipher;

impl StreamCipher for DummyCipher {
    fn update(&mut self, data: &[u8], out: &mut dyn BufMut) -> CipherResult<()> {
        out.put_slice(data);
        Ok(())
    }

    fn finalize(&mut self, _: &mut dyn BufMut) -> CipherResult<()> {
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}
