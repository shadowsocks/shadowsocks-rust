// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

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

//! Cipher defined with Rust binding for libcrypto (OpenSSL)

use std::convert::From;

use crypto::cipher::{Cipher, CipherType, CipherResult};
use crypto::cipher;

use crypto::CryptoMode;

use openssl::symm;

/// Core cipher of OpenSSL
pub struct OpenSSLCrypto {
    cipher: symm::Cipher,
    inner: symm::Crypter,
}

impl OpenSSLCrypto {
    /// Creates by type
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let t = match cipher_type {
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb => symm::Cipher::aes_128_cfb128(),
            #[cfg(feature = "cipher-aes-cfb1")]
            CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1(),
            #[cfg(feature = "cipher-aes-cfb128")]
            CipherType::Aes128Cfb128 => symm::Cipher::aes_128_cfb128(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb => symm::Cipher::aes_256_cfb128(),
            #[cfg(feature = "cipher-aes-cfb1")]
            CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1(),
            #[cfg(feature = "cipher-aes-cfb128")]
            CipherType::Aes256Cfb128 => symm::Cipher::aes_256_cfb128(),

            #[cfg(feature = "cipher-rc4")]
            CipherType::Rc4 => symm::Cipher::rc4(),
            _ => {
                panic!("Cipher type {:?} does not supported by OpenSSLCrypt yet",
                       cipher_type)
            }
        };

        // Panic if error occurs
        let cipher = symm::Crypter::new(t, From::from(mode), key, Some(iv)).unwrap();

        OpenSSLCrypto {
            cipher: t,
            inner: cipher,
        }
    }

    /// Update data
    pub fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        let orig_length = out.len();
        let least_reserved = data.len() + self.cipher.block_size();
        out.resize(orig_length + least_reserved, 0);
        let length = try!(self.inner.update(data, &mut out[orig_length..]));
        out.resize(orig_length + length, 0);
        Ok(())
    }

    /// Generate the final block
    pub fn finalize(&mut self, out: &mut Vec<u8>) -> CipherResult<()> {
        let orig_length = out.len();
        let least_reserved = self.cipher.block_size();
        out.resize(orig_length + least_reserved, 0);
        let length = try!(self.inner.finalize(&mut out[orig_length..]));
        out.resize(orig_length + length, 0);
        Ok(())
    }
}

/// The Cipher binding for OpenSSL's `libcrypto`.
///
/// It should be noticed that the decipher needs to read the iv (initialization vector)
/// from the first call of `decrypt`. So the cipher will have to insert the iv into
/// the front of the encrypted data.
///
/// *Note: This behavior works just the same as the official version of shadowsocks.*
///
/// ```rust
/// use shadowsocks::crypto::CryptoMode;
/// use shadowsocks::crypto::cipher::CipherType;
/// use shadowsocks::crypto::openssl::OpenSSLCipher;
/// use shadowsocks::crypto::cipher::Cipher;
///
/// let method = CipherType::Aes128Cfb;
///
/// let key = method.bytes_to_key(b"password");
/// let iv = method.gen_init_vec();
///
/// let mut enc = OpenSSLCipher::new(method, &key[0..], &iv[0..], CryptoMode::Encrypt);
/// let mut dec = OpenSSLCipher::new(method, &key[0..], &iv[0..], CryptoMode::Decrypt);
///
/// let message = "hello world";
/// let mut encrypted_message = Vec::new();
/// enc.update(message.as_bytes(), &mut encrypted_message).unwrap();
///
/// let mut decrypted_message = Vec::new();
/// dec.update(&encrypted_message[..], &mut decrypted_message).unwrap();
///
/// assert!(&decrypted_message[..] == message.as_bytes());
/// ```
pub struct OpenSSLCipher {
    worker: OpenSSLCrypto,
}

impl OpenSSLCipher {
    /// Creates by type
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCipher {
        OpenSSLCipher { worker: OpenSSLCrypto::new(cipher_type, &key[..], &iv[..], mode) }
    }
}

unsafe impl Send for OpenSSLCipher {}

impl Cipher for OpenSSLCipher {
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        self.worker.update(data, out)
    }

    fn finalize(&mut self, out: &mut Vec<u8>) -> CipherResult<()> {
        self.worker.finalize(out)
    }
}
