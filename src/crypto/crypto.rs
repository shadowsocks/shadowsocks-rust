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

use rust_crypto::symmetriccipher::SynchronousStreamCipher;
use rust_crypto::chacha20::ChaCha20;
use rust_crypto::salsa20::Salsa20;

use crypto::cipher::{StreamCipher, CipherType, CipherResult};

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

#[cfg(test)]
mod test {
    use crypto::cipher::{Cipher, CipherType};
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
