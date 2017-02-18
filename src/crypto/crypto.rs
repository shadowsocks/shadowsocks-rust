// The MIT License (MIT)

// Copyright (c) 2015 Y. T. Chung

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Cipher defined with Rust-Crypto

use std::mem;

use rust_crypto::symmetriccipher::SynchronousStreamCipher;
use rust_crypto::chacha20::ChaCha20;
use rust_crypto::salsa20::Salsa20;
use rust_crypto::aes_gcm::AesGcm;
use rust_crypto::aes::KeySize;

use crypto::{StreamCipher, CipherType, CipherResult};
use crypto::{AeadDecryptor, AeadEncryptor};
use crypto::cipher::Error;
use crypto::aead::{make_skey, increase_nonce};

/// Cipher provided by Rust-Crypto
pub enum CryptoCipher {
    ChaCha20(ChaCha20),
    Salsa20(Salsa20),
}

impl CryptoCipher {
    /// Creates an instance
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> CryptoCipher {
        match t {
            CipherType::ChaCha20 => CryptoCipher::ChaCha20(ChaCha20::new(key, iv)),
            CipherType::Salsa20 => CryptoCipher::Salsa20(Salsa20::new(key, iv)),
            _ => panic!("Rust Crypto does not support {:?} cipher", t),
        }
    }
}

impl StreamCipher for CryptoCipher {
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        out.reserve(data.len());
        let orig_len = out.len();
        unsafe {
            out.set_len(orig_len + data.len());
        }
        let mut out = &mut out[orig_len..];

        match *self {
            CryptoCipher::ChaCha20(ref mut cipher) => cipher.process(data, out),
            CryptoCipher::Salsa20(ref mut cipher) => cipher.process(data, out),
        }

        Ok(())
    }

    fn finalize(&mut self, _: &mut Vec<u8>) -> CipherResult<()> {
        Ok(())
    }
}

/// AEAD ciphers provided by Rust-Crypto
pub enum CryptoAeadCryptoVariant {
    AesGcm(AesGcm<'static>),
}

/// AEAD Cipher context
///
/// According to SIP004, the `nounce` has to incr 1 after each encrypt/decrypt.
pub struct CryptoAeadCrypto {
    cipher: CryptoAeadCryptoVariant,
    cipher_type: CipherType,
    key: Vec<u8>,
    nonce: Vec<u8>,
}

impl CryptoAeadCrypto {
    /// Initialize context
    pub fn new(t: CipherType, key: &[u8], salt: &[u8]) -> CryptoAeadCrypto {
        // TODO: Check if salt is duplicated

        let nonce_size = t.iv_size();
        let nonce = vec![0u8; nonce_size];
        let skey = make_skey(t, key, salt);
        let cipher = CryptoAeadCrypto::new_variant(t, &skey, &nonce);
        CryptoAeadCrypto {
            cipher: cipher,
            cipher_type: t,
            key: skey,
            nonce: nonce,
        }
    }

    fn new_variant(t: CipherType, key: &[u8], nonce: &[u8]) -> CryptoAeadCryptoVariant {
        match t {
            CipherType::Aes128Gcm => CryptoAeadCryptoVariant::AesGcm(AesGcm::new(KeySize::KeySize128, key, nonce, &[])),
            CipherType::Aes192Gcm => CryptoAeadCryptoVariant::AesGcm(AesGcm::new(KeySize::KeySize192, key, nonce, &[])),
            CipherType::Aes256Gcm => CryptoAeadCryptoVariant::AesGcm(AesGcm::new(KeySize::KeySize256, key, nonce, &[])),

            _ => panic!("Unsupported {:?}", t),
        }
    }

    fn increase_nonce(&mut self) {
        increase_nonce(&mut self.nonce);
    }

    fn reset(&mut self) {
        self.increase_nonce();
        let var = CryptoAeadCrypto::new_variant(self.cipher_type, &self.key, &self.nonce);
        mem::replace(&mut self.cipher, var);
    }
}

impl AeadEncryptor for CryptoAeadCrypto {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]) {
        use rust_crypto::aead::AeadEncryptor;

        {
            let CryptoAeadCrypto { ref mut cipher, .. } = *self;
            match *cipher {
                CryptoAeadCryptoVariant::AesGcm(ref mut gcm) => {
                    gcm.encrypt(input, output, tag);
                }
            }
        }

        self.reset();
    }
}

impl AeadDecryptor for CryptoAeadCrypto {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> CipherResult<()> {
        use rust_crypto::aead::AeadDecryptor;

        let r = {
            let CryptoAeadCrypto { ref mut cipher, .. } = *self;
            match *cipher {
                CryptoAeadCryptoVariant::AesGcm(ref mut gcm) => {
                    if !gcm.decrypt(input, output, tag) {
                        Err(Error::AeadDecryptFailed)
                    } else {
                        Ok(())
                    }
                }
            }
        };

        self.reset();

        r
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

        let mut enc = CryptoCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::new();
        enc.update(message, &mut encrypted_msg).unwrap();

        let mut dec = CryptoCipher::new(ct, &key[..], &iv[..]);
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

        let mut enc = CryptoCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::new();
        enc.update(message, &mut encrypted_msg).unwrap();

        let mut dec = CryptoCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }
}
