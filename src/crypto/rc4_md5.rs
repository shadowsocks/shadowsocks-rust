//! Rc4Md5 cipher definition

use crate::crypto::{openssl::OpenSSLCrypto, CipherResult, CipherType, CryptoMode, StreamCipher};

use bytes::BufMut;
use digest::Digest;
use md5::Md5;

/// Rc4Md5 Cipher
pub struct Rc4Md5Cipher {
    crypto: OpenSSLCrypto,
}

impl Rc4Md5Cipher {
    pub fn new(key: &[u8], iv: &[u8], mode: CryptoMode) -> Rc4Md5Cipher {
        let mut md5_digest = Md5::new();
        md5_digest.input(key);
        md5_digest.input(iv);

        let key = md5_digest.result();

        Rc4Md5Cipher {
            crypto: OpenSSLCrypto::new(CipherType::Rc4, &key, b"", mode),
        }
    }
}

impl StreamCipher for Rc4Md5Cipher {
    fn update(&mut self, data: &[u8], out: &mut dyn BufMut) -> CipherResult<()> {
        self.crypto.update(data, out)
    }

    fn finalize(&mut self, out: &mut dyn BufMut) -> CipherResult<()> {
        self.crypto.finalize(out)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.crypto.buffer_size(data)
    }
}

unsafe impl Send for Rc4Md5Cipher {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{CipherType, CryptoMode, StreamCipher};

    #[test]
    fn test_rc4_md5_cipher() {
        let msg = b"abcd1234";
        let key = b"key";

        let t = CipherType::Rc4Md5;
        let iv = t.gen_init_vec();

        let mut enc = Rc4Md5Cipher::new(key, &iv[..], CryptoMode::Encrypt);
        let mut encrypted_msg = Vec::new();
        enc.update(msg, &mut encrypted_msg)
            .and_then(|_| enc.finalize(&mut encrypted_msg))
            .unwrap();

        let mut dec = Rc4Md5Cipher::new(key, &iv[..], CryptoMode::Decrypt);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[..], &mut decrypted_msg)
            .and_then(|_| dec.finalize(&mut decrypted_msg))
            .unwrap();

        assert_eq!(msg, &decrypted_msg[..]);
    }
}
