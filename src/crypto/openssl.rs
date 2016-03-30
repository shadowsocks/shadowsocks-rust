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
use std::io::Write;

use crypto::cipher::{Cipher, CipherType, CipherResult};
use crypto::cipher;

use crypto::digest::Digest;
use crypto::digest;
use crypto::CryptoMode;

use openssl::crypto::symm;
use openssl::crypto::hash;

pub struct OpenSSLCrypto {
    inner: symm::Crypter,
}

impl OpenSSLCrypto {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let t = match cipher_type {
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb => symm::Type::AES_128_CFB128,
            #[cfg(feature = "cipher-aes-cfb1")]
            CipherType::Aes128Cfb1 => symm::Type::AES_128_CFB1,
            #[cfg(feature = "cipher-aes-cfb128")]
            CipherType::Aes128Cfb128 => symm::Type::AES_128_CFB128,
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb => symm::Type::AES_256_CFB128,
            #[cfg(feature = "cipher-aes-cfb1")]
            CipherType::Aes256Cfb1 => symm::Type::AES_256_CFB1,
            #[cfg(feature = "cipher-aes-cfb128")]
            CipherType::Aes256Cfb128 => symm::Type::AES_256_CFB128,

            #[cfg(feature = "cipher-rc4")]
            CipherType::Rc4 => symm::Type::RC4_128,
            _ => panic!("Cipher type {:?} does not supported by OpenSSLCrypt yet", cipher_type),
        };

        let cipher = symm::Crypter::new(t);
        cipher.init(From::from(mode), key, iv);

        OpenSSLCrypto {
            inner: cipher,
        }
    }

    pub fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        let output = self.inner.update(data);
        out.extend_from_slice(&output);
        Ok(())
    }

    pub fn finalize(&mut self, out: &mut Vec<u8>) -> CipherResult<()> {
        let output = self.inner.finalize();
        out.extend_from_slice(&output);
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
/// use shadowsocks::crypto::cipher;
/// use shadowsocks::crypto::openssl::OpenSSLCipher;
/// use shadowsocks::crypto::cipher::Cipher;
///
/// let key = cipher::CipherType::Aes128Cfb.bytes_to_key(b"password");
/// let iv = cipher::CipherType::Aes128Cfb.gen_init_vec();
///
/// let mut enc = OpenSSLCipher::new(cipher::CipherType::Aes128Cfb, &key[0..], &iv[0..], CryptoMode::Encrypt);
/// let mut dec = OpenSSLCipher::new(cipher::CipherType::Aes128Cfb, &key[0..], &iv[0..], CryptoMode::Decrypt);
/// let message = "hello world";
/// let mut encrypted_message = Vec::new();
/// enc.update(message.as_bytes(), &mut encrypted_message).unwrap();
/// let mut decrypted_message = Vec::new();
/// dec.update(&encrypted_message[..], &mut decrypted_message).unwrap();
///
/// assert!(&decrypted_message[..] == message.as_bytes());
/// ```
pub struct OpenSSLCipher {
    worker: OpenSSLCrypto,
}

impl OpenSSLCipher {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCipher {
        OpenSSLCipher {
            worker: OpenSSLCrypto::new(cipher_type, &key[..], &iv[..], mode),
        }
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

pub struct OpenSSLDigest {
    inner: hash::Hasher,
}

impl OpenSSLDigest {
    pub fn new(t: digest::DigestType) -> OpenSSLDigest {
        let t = match t {
            digest::DigestType::Md5 => hash::Type::MD5,
            digest::DigestType::Sha => hash::Type::SHA512,
            digest::DigestType::Sha1 => hash::Type::SHA1,
        };

        OpenSSLDigest {
            inner: hash::Hasher::new(t),
        }
    }
}

unsafe impl Send for OpenSSLDigest {}

impl Digest for OpenSSLDigest {
    fn update(&mut self, data: &[u8]) {
        let _ = self.inner.write(data);
    }

    fn digest(&mut self) -> Vec<u8> {
        self.inner.finish()
    }
}
