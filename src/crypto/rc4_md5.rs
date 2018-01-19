//! Rc4Md5 cipher definition

use crypto::{CipherResult, CipherType, StreamCipher};
use crypto::CryptoMode;
use crypto::digest::{self, Digest, DigestType};
use crypto::openssl::OpenSSLCrypto;

use bytes::{BufMut, BytesMut};

/// Rc4Md5 Cipher
pub struct Rc4Md5Cipher {
    crypto: OpenSSLCrypto,
}

impl Rc4Md5Cipher {
    pub fn new(key: &[u8], iv: &[u8], mode: CryptoMode) -> Rc4Md5Cipher {
        let mut md5_digest = digest::with_type(DigestType::Md5);
        md5_digest.update(key);
        md5_digest.update(iv);
        let mut key = BytesMut::with_capacity(md5_digest.digest_len());
        md5_digest.digest(&mut key);

        Rc4Md5Cipher { crypto: OpenSSLCrypto::new(CipherType::Rc4, &key, b"", mode), }
    }
}

impl StreamCipher for Rc4Md5Cipher {
    fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        self.crypto.update(data, out)
    }

    fn finalize<B: BufMut>(&mut self, out: &mut B) -> CipherResult<()> {
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
    use crypto::{CipherType, StreamCipher};
    use crypto::CryptoMode;

    #[test]
    fn test_rc4_md5_cipher() {
        let msg = b"abcd1234";
        let key = b"key";

        let t = CipherType::Rc4Md5;
        let iv = t.gen_init_vec();

        let mut enc = Rc4Md5Cipher::new(key, &iv[..], CryptoMode::Encrypt);
        let mut encrypted_msg = Vec::new();
        enc.update(msg, &mut encrypted_msg).and_then(|_| enc.finalize(&mut encrypted_msg))
           .unwrap();

        let mut dec = Rc4Md5Cipher::new(key, &iv[..], CryptoMode::Decrypt);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[..], &mut decrypted_msg).and_then(|_| dec.finalize(&mut decrypted_msg))
           .unwrap();

        assert_eq!(msg, &decrypted_msg[..]);
    }
}
