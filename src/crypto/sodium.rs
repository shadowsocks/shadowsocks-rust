//! Cipher defined with libsodium

use bytes::BufMut;
use sodiumoxide::crypto::stream::{chacha20, salsa20, xsalsa20, aes128ctr};

use crypto::{StreamCipher, CipherType, CipherResult};


/// Cipher provided by Rust-Crypto
pub enum SodiumCipher {
    ChaCha20(chacha20::Key, chacha20::Nonce),
    Salsa20(salsa20::Key, salsa20::Nonce),
    XSalsa20(xsalsa20::Key, xsalsa20::Nonce),
    Aes128Ctr(aes128ctr::Key, aes128ctr::Nonce),
}

impl SodiumCipher {
    /// Creates an instance
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> SodiumCipher {
        match t {
            CipherType::ChaCha20 => {
                SodiumCipher::ChaCha20(
                    chacha20::Key::from_slice(key).unwrap(),
                    chacha20::Nonce::from_slice(iv).unwrap(),
                )
            }
            CipherType::Salsa20 => {
                SodiumCipher::Salsa20(
                    salsa20::Key::from_slice(key).unwrap(),
                    salsa20::Nonce::from_slice(iv).unwrap(),
                )
            }
            CipherType::XSalsa20 => {
                SodiumCipher::XSalsa20(
                    xsalsa20::Key::from_slice(key).unwrap(),
                    xsalsa20::Nonce::from_slice(iv).unwrap(),
                )
            }
            CipherType::Aes128Ctr => {
                SodiumCipher::Aes128Ctr(
                    aes128ctr::Key::from_slice(key).unwrap(),
                    aes128ctr::Nonce::from_slice(iv).unwrap(),
                )
            }
            _ => panic!("Rust Crypto does not support {:?} cipher", t),
        }
    }
}

impl StreamCipher for SodiumCipher {
    fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        match *self {
            SodiumCipher::ChaCha20(ref key, ref nonce) => out.put(chacha20::stream_xor(data, nonce, key)),
            SodiumCipher::Salsa20(ref key, ref nonce) => out.put(salsa20::stream_xor(data, nonce, key)),
            SodiumCipher::XSalsa20(ref key, ref nonce) => out.put(xsalsa20::stream_xor(data, nonce, key)),
            SodiumCipher::Aes128Ctr(ref key, ref nonce) => out.put(aes128ctr::stream_xor(data, nonce, key)),
        }

        Ok(())
    }

    fn finalize<B: BufMut>(&mut self, _: &mut B) -> CipherResult<()> {
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}



#[cfg(test)]
mod test {
    use crypto::{StreamCipher, CipherType};
    use super::*;

    #[test]
    fn test_rust_crypto_cipher_chacha20() {
        let ct = CipherType::ChaCha20;

        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::new();
        enc.update(message, &mut encrypted_msg).unwrap();

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    #[test]
    fn test_rust_crypto_cipher_salsa20() {
        let ct = CipherType::Salsa20;

        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::new();
        enc.update(message, &mut encrypted_msg).unwrap();

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }
}
