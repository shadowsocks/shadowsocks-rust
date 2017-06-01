//! Cipher defined with Rust-Crypto

use std::mem;

#[cfg(feature = "rust-crypto")]
use rust_crypto::symmetriccipher::SynchronousStreamCipher;
#[cfg(feature = "rust-crypto")]
use rust_crypto::chacha20::ChaCha20;
#[cfg(feature = "rust-crypto")]
use rust_crypto::salsa20::Salsa20;

use ring::aead::{
    AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
    SealingKey, OpeningKey,
    seal_in_place, open_in_place
};

use crypto::{StreamCipher, CipherType, CipherResult};
use crypto::{AeadDecryptor, AeadEncryptor};
use crypto::cipher::Error;
use crypto::aead::{make_skey, increase_nonce};

use bytes::{BytesMut, BufMut, Bytes};
use bytes::buf::FromBuf;

/// Cipher provided by Rust-Crypto
pub enum CryptoCipher {
    #[cfg(feature = "rust-crypto")]
    ChaCha20(ChaCha20),
    #[cfg(feature = "rust-crypto")]
    Salsa20(Salsa20),
}

impl CryptoCipher {
    /// Creates an instance
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> CryptoCipher {
        match t {
            #[cfg(feature = "rust-crypto")]
            CipherType::ChaCha20 => CryptoCipher::ChaCha20(ChaCha20::new(key, iv)),
            #[cfg(feature = "rust-crypto")]
            CipherType::Salsa20 => CryptoCipher::Salsa20(Salsa20::new(key, iv)),
            _ => panic!("Rust Crypto does not support {:?} cipher", t),
        }
    }
}

impl StreamCipher for CryptoCipher {
    fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        let mut buf = BytesMut::with_capacity(self.buffer_size(data));
        unsafe { buf.set_len(self.buffer_size(data)) }; // NOTE: Set length
        assert_eq!(buf.len(), data.len());
        match *self {
            #[cfg(feature = "rust-crypto")]
            CryptoCipher::ChaCha20(ref mut cipher) => cipher.process(data, &mut *buf),
            #[cfg(feature = "rust-crypto")]
            CryptoCipher::Salsa20(ref mut cipher) => cipher.process(data, &mut *buf),
        }
        out.put(buf);

        Ok(())
    }

    fn finalize<B: BufMut>(&mut self, _: &mut B) -> CipherResult<()> {
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}

/// AEAD ciphers provided by Rust-Crypto
pub enum CryptoAeadCryptoVariant {
    Seal(SealingKey, Bytes),
    Open(OpeningKey, Bytes),
}

/// AEAD Cipher context
///
/// According to SIP004, the `nounce` has to incr 1 after each encrypt/decrypt.
pub struct CryptoAeadCrypto {
    cipher: CryptoAeadCryptoVariant,
    cipher_type: CipherType,
    key: Bytes,
    nonce: BytesMut,
}

impl CryptoAeadCrypto {
    /// Initialize context
    pub fn new(t: CipherType, key: &[u8], salt: &[u8], is_encrypt: bool) -> CryptoAeadCrypto {
        // TODO: Check if salt is duplicated

        let nonce_size = t.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        for _ in 0..nonce_size {
            nonce.put_u8(0);
        }

        let skey = make_skey(t, key, salt);
        let cipher = CryptoAeadCrypto::new_variant(t, &skey, &nonce, is_encrypt);
        CryptoAeadCrypto {
            cipher: cipher,
            cipher_type: t,
            key: skey,
            nonce: nonce,
        }
    }

    fn new_variant(t: CipherType, key: &[u8], nonce: &[u8], is_encrypt: bool) -> CryptoAeadCryptoVariant {
        match t {
            CipherType::Aes128Gcm => if is_encrypt {
                CryptoAeadCryptoVariant::Seal(SealingKey::new(&AES_128_GCM, key).unwrap(), Bytes::from_buf(nonce))
            } else {
                CryptoAeadCryptoVariant::Open(OpeningKey::new(&AES_128_GCM, key).unwrap(), Bytes::from_buf(nonce))
            },
            CipherType::Aes256Gcm => if is_encrypt {
                CryptoAeadCryptoVariant::Seal(SealingKey::new(&AES_256_GCM, key).unwrap(), Bytes::from_buf(nonce))
            } else {
                CryptoAeadCryptoVariant::Open(OpeningKey::new(&AES_256_GCM, key).unwrap(), Bytes::from_buf(nonce))
            },
            CipherType::ChaCha20Poly1305 => if is_encrypt {
                CryptoAeadCryptoVariant::Seal(SealingKey::new(&CHACHA20_POLY1305, key).unwrap(), Bytes::from_buf(nonce))
            } else {
                CryptoAeadCryptoVariant::Open(OpeningKey::new(&CHACHA20_POLY1305, key).unwrap(), Bytes::from_buf(nonce))
            },

            _ => panic!("Unsupported {:?}", t),
        }
    }

    fn increase_nonce(&mut self) {
        increase_nonce(&mut self.nonce);
    }

    fn reset(&mut self) {
        self.increase_nonce();
        let is_encrypt = match self.cipher {
            CryptoAeadCryptoVariant::Seal(..) => true,
            CryptoAeadCryptoVariant::Open(..) => false
        };
        let var = CryptoAeadCrypto::new_variant(self.cipher_type, &self.key, &self.nonce, is_encrypt);
        mem::replace(&mut self.cipher, var);
    }
}

impl AeadEncryptor for CryptoAeadCrypto {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]) {
        let tag_len = tag.len();

        let mut buf = BytesMut::with_capacity(input.len() + tag_len);
        buf.put(input);
        buf.put_slice(tag);

        if let CryptoAeadCryptoVariant::Seal(ref key, ref nonce) = self.cipher {
            seal_in_place(key, nonce, &[], &mut buf, tag_len).unwrap();
            let (ct, t) = buf.split_at(buf.len() - tag_len);
            output.clone_from_slice(ct);
            tag.clone_from_slice(t);
        } else {
            panic!();
        }

        self.reset();
    }
}

impl AeadDecryptor for CryptoAeadCrypto {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> CipherResult<()> {
        let mut buf = BytesMut::with_capacity(input.len() + tag.len());
        buf.put(input);
        buf.put(tag);

        let r = if let CryptoAeadCryptoVariant::Open(ref key, ref nonce) = self.cipher {
            match open_in_place(key, nonce, &[], 0, &mut buf) {
                Ok(buf) => {
                    output.clone_from_slice(&buf[..input.len()]);
                    Ok(())
                },
                Err(_) => Err(Error::AeadDecryptFailed)
            }
        } else {
            panic!()
        };

        self.reset();

        r
    }
}

#[cfg(test)]
mod test {
    use crypto::{StreamCipher, CipherType};
    use super::*;

    #[cfg(feature = "rust-crypto")]
    #[test]
    fn test_rust_crypto_cipher_chacha20() {
        let ct = CipherType::ChaCha20;

        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = CryptoCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::new();
        enc.update(message, &mut encrypted_msg).unwrap();

        let mut dec = CryptoCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    #[cfg(feature = "rust-crypto")]
    #[test]
    fn test_rust_crypto_cipher_salsa20() {
        let ct = CipherType::Salsa20;

        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = CryptoCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::new();
        enc.update(message, &mut encrypted_msg).unwrap();

        let mut dec = CryptoCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }
}
