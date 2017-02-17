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

//! Ciphers

use std::str::{self, FromStr};
use std::fmt::{self, Debug, Display};
use std::io;
use rand::{self, Rng};
use std::convert::From;

use crypto::digest::{self, DigestType, Digest};

use openssl::symm;

#[cfg(feature = "key-derive-argon2")]
use argon2rs::{Argon2, Variant};

/// Cipher result
pub type CipherResult<T> = Result<T, Error>;

/// Cipher error
pub enum Error {
    UnknownCipherType,
    OpenSSLError(::openssl::error::ErrorStack),
    IoError(io::Error),
    AeadDecryptFailed,
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            Error::OpenSSLError(ref err) => write!(f, "{:?}", err),
            Error::IoError(ref err) => write!(f, "{:?}", err),
            Error::AeadDecryptFailed => write!(f, "AEAD decrypt failed"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            Error::OpenSSLError(ref err) => write!(f, "{}", err),
            Error::IoError(ref err) => write!(f, "{}", err),
            Error::AeadDecryptFailed => write!(f, "AeadDecryptFailed"),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::UnknownCipherType => io::Error::new(io::ErrorKind::Other, "Unknown Cipher type"),
            Error::OpenSSLError(err) => From::from(err),
            Error::IoError(err) => err,
            Error::AeadDecryptFailed => io::Error::new(io::ErrorKind::Other, "AEAD decrypt error"),
        }
    }
}

impl From<::openssl::error::ErrorStack> for Error {
    fn from(e: ::openssl::error::ErrorStack) -> Error {
        Error::OpenSSLError(e)
    }
}

const CIPHER_AES_128_CFB: &'static str = "aes-128-cfb";
const CIPHER_AES_128_CFB_1: &'static str = "aes-128-cfb1";
const CIPHER_AES_128_CFB_8: &'static str = "aes-128-cfb8";
const CIPHER_AES_128_CFB_128: &'static str = "aes-128-cfb128";

const CIPHER_AES_256_CFB: &'static str = "aes-256-cfb";
const CIPHER_AES_256_CFB_1: &'static str = "aes-256-cfb1";
const CIPHER_AES_256_CFB_8: &'static str = "aes-256-cfb8";
const CIPHER_AES_256_CFB_128: &'static str = "aes-256-cfb128";

const CIPHER_RC4: &'static str = "rc4";
const CIPHER_RC4_MD5: &'static str = "rc4-md5";

const CIPHER_TABLE: &'static str = "table";

const CIPHER_CHACHA20: &'static str = "chacha20";
const CIPHER_SALSA20: &'static str = "salsa20";

const CIPHER_DUMMY: &'static str = "dummy";

const CIPHER_AES_128_GCM: &'static str = "aes-128-gcm";
const CIPHER_AES_192_GCM: &'static str = "aes-192-gcm";
const CIPHER_AES_256_GCM: &'static str = "aes-256-gcm";

/// ShadowSocks cipher type
#[derive(Clone, Debug, Copy)]
pub enum CipherType {
    Table,
    Dummy,

    Aes128Cfb,
    Aes128Cfb1,
    Aes128Cfb8,
    Aes128Cfb128,

    Aes256Cfb,
    Aes256Cfb1,
    Aes256Cfb8,
    Aes256Cfb128,

    Rc4,
    Rc4Md5,

    ChaCha20,
    Salsa20,

    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CipherCategory {
    Stream,
    Aead,
}

impl CipherType {
    /// Symmetric crypto key size
    pub fn key_size(&self) -> usize {
        match *self {
            CipherType::Table | CipherType::Dummy => 0,

            CipherType::Aes128Cfb => symm::Cipher::aes_128_cfb128().key_len(),
            CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1().key_len(),
            CipherType::Aes128Cfb8 => symm::Cipher::aes_128_cfb8().key_len(),
            CipherType::Aes128Cfb128 => symm::Cipher::aes_128_cfb128().key_len(),
            CipherType::Aes256Cfb => symm::Cipher::aes_256_cfb128().key_len(),
            CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1().key_len(),
            CipherType::Aes256Cfb8 => symm::Cipher::aes_256_cfb8().key_len(),
            CipherType::Aes256Cfb128 => symm::Cipher::aes_256_cfb128().key_len(),

            CipherType::Rc4 => symm::Cipher::rc4().key_len(),
            CipherType::Rc4Md5 => symm::Cipher::rc4().key_len(),

            CipherType::ChaCha20 => 32,
            CipherType::Salsa20 => 32,

            CipherType::Aes128Gcm => 16,
            CipherType::Aes192Gcm => 24,
            CipherType::Aes256Gcm => 32,
        }
    }

    /// Extends key to match the required key length
    #[cfg(not(feature = "key-derive-argon2"))]
    pub fn bytes_to_key(&self, key: &[u8]) -> Vec<u8> {
        let iv_len = self.iv_size();
        let key_len = self.key_size();

        let mut digest = digest::with_type(DigestType::Md5);

        let mut result = Vec::new();
        let mut m = Vec::new();
        let mut loop_count = 0;
        while loop_count * digest.digest_len() < (key_len + iv_len) {
            let mut vkey = m.clone();
            vkey.extend_from_slice(key);

            digest.update(&vkey);

            m.clear();
            digest.digest(&mut m);
            loop_count += 1;

            digest.reset();

            result.extend_from_slice(&m[..]);
        }

        result.resize(key_len, 0);
        result
    }

    #[cfg(feature = "key-derive-argon2")]
    fn aead_key_derive(&self, key: &[u8]) -> Vec<u8> {
        // We should use crypto_pwhash in libsodium
        // Salt is b"shadowsocks hash"
        // Already implemented in shadowsocks-libev
        // Ref:  crypto_pwhash (key, nkey, (char*)pass, strlen(pass), salt,
        //         crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
        //         crypto_pwhash_ALG_DEFAULT);

        const SALT: &'static [u8] = b"shadowsocks hash";

        let key_len = self.key_size();
        let mut buf = vec![0u8; key_len];
        let a2 = Argon2::default(Variant::Argon2i); // NOTE, libsodium uses 2i as crypto_pwhash_ALG_DEFAULT
        a2.hash(&mut buf, key, SALT, &[], &[]);
        buf
    }

    /// Extends key to match the required key length
    #[cfg(feature = "key-derive-argon2")]
    pub fn bytes_to_key(&self, key: &[u8]) -> Vec<u8> {
        match self.category() {
            CipherCategory::Aead => self.aead_key_derive(key),
            CipherCategory::Stream => {
                let iv_len = self.iv_size();
                let key_len = self.key_size();

                let mut digest = digest::with_type(DigestType::Md5);

                let mut result = Vec::new();
                let mut m = Vec::new();
                let mut loop_count = 0;
                while loop_count * digest.digest_len() < (key_len + iv_len) {
                    let mut vkey = m.clone();
                    vkey.extend_from_slice(key);

                    digest.update(&vkey);

                    m.clear();
                    digest.digest(&mut m);
                    loop_count += 1;

                    digest.reset();

                    result.extend_from_slice(&m[..]);
                }

                result.resize(key_len, 0);
                result
            }
        }
    }

    /// Symmetric crypto initialize vector size
    pub fn iv_size(&self) -> usize {
        match *self {
            CipherType::Table | CipherType::Dummy => 0,

            CipherType::Aes128Cfb => symm::Cipher::aes_128_cfb128().iv_len().unwrap_or(0),
            CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1().iv_len().unwrap_or(0),
            CipherType::Aes128Cfb8 => symm::Cipher::aes_128_cfb8().iv_len().unwrap_or(0),
            CipherType::Aes128Cfb128 => symm::Cipher::aes_128_cfb128().iv_len().unwrap_or(0),
            CipherType::Aes256Cfb => symm::Cipher::aes_256_cfb128().iv_len().unwrap_or(0),
            CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1().iv_len().unwrap_or(0),
            CipherType::Aes256Cfb8 => symm::Cipher::aes_256_cfb8().iv_len().unwrap_or(0),
            CipherType::Aes256Cfb128 => symm::Cipher::aes_256_cfb128().iv_len().unwrap_or(0),

            CipherType::Rc4 => symm::Cipher::rc4().iv_len().unwrap_or(0),
            CipherType::Rc4Md5 => symm::Cipher::rc4().iv_len().unwrap_or(0),

            CipherType::ChaCha20 => 8,
            CipherType::Salsa20 => 8,

            CipherType::Aes128Gcm |
            CipherType::Aes192Gcm |
            CipherType::Aes256Gcm => 12,
        }
    }

    fn gen_random_bytes(len: usize) -> Vec<u8> {
        let mut iv = Vec::with_capacity(len);
        unsafe {
            iv.set_len(len);
        }
        rand::thread_rng().fill_bytes(iv.as_mut_slice());

        iv
    }

    /// Generate a random initialize vector for this cipher
    pub fn gen_init_vec(&self) -> Vec<u8> {
        let iv_len = self.iv_size();
        CipherType::gen_random_bytes(iv_len)
    }

    /// Get category of cipher
    pub fn category(&self) -> CipherCategory {
        match *self {
            CipherType::Aes128Gcm |
            CipherType::Aes192Gcm |
            CipherType::Aes256Gcm => CipherCategory::Aead,
            _ => CipherCategory::Stream,
        }
    }

    /// Get tag size for AEAD Ciphers
    pub fn tag_size(&self) -> usize {
        assert!(self.category() == CipherCategory::Aead);

        match *self {
            CipherType::Aes128Gcm |
            CipherType::Aes192Gcm |
            CipherType::Aes256Gcm => 16,

            _ => panic!("Only support AEAD ciphers, found {:?}", self),
        }
    }

    /// Get nonce size for AEAD ciphers
    pub fn salt_size(&self) -> usize {
        assert!(self.category() == CipherCategory::Aead);
        self.key_size()
    }

    /// Get salt for AEAD ciphers
    pub fn gen_salt(&self) -> Vec<u8> {
        CipherType::gen_random_bytes(self.salt_size())
    }
}

impl FromStr for CipherType {
    type Err = Error;
    fn from_str(s: &str) -> Result<CipherType, Error> {
        match s {
            CIPHER_TABLE | "" => Ok(CipherType::Table),
            CIPHER_DUMMY => Ok(CipherType::Dummy),
            CIPHER_AES_128_CFB => Ok(CipherType::Aes128Cfb),
            CIPHER_AES_128_CFB_1 => Ok(CipherType::Aes128Cfb1),
            CIPHER_AES_128_CFB_8 => Ok(CipherType::Aes128Cfb8),
            CIPHER_AES_128_CFB_128 => Ok(CipherType::Aes128Cfb128),

            CIPHER_AES_256_CFB => Ok(CipherType::Aes256Cfb),
            CIPHER_AES_256_CFB_1 => Ok(CipherType::Aes256Cfb1),
            CIPHER_AES_256_CFB_8 => Ok(CipherType::Aes256Cfb8),
            CIPHER_AES_256_CFB_128 => Ok(CipherType::Aes256Cfb128),

            CIPHER_RC4 => Ok(CipherType::Rc4),
            CIPHER_RC4_MD5 => Ok(CipherType::Rc4Md5),

            CIPHER_CHACHA20 => Ok(CipherType::ChaCha20),
            CIPHER_SALSA20 => Ok(CipherType::Salsa20),

            CIPHER_AES_128_GCM => Ok(CipherType::Aes128Gcm),
            CIPHER_AES_192_GCM => Ok(CipherType::Aes192Gcm),
            CIPHER_AES_256_GCM => Ok(CipherType::Aes256Gcm),

            _ => Err(Error::UnknownCipherType),
        }
    }
}

impl Display for CipherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherType::Table => write!(f, "{}", CIPHER_TABLE),
            CipherType::Dummy => write!(f, "{}", CIPHER_DUMMY),
            CipherType::Aes128Cfb => write!(f, "{}", CIPHER_AES_128_CFB),
            CipherType::Aes128Cfb1 => write!(f, "{}", CIPHER_AES_128_CFB_1),
            CipherType::Aes128Cfb8 => write!(f, "{}", CIPHER_AES_128_CFB_8),
            CipherType::Aes128Cfb128 => write!(f, "{}", CIPHER_AES_128_CFB_128),

            CipherType::Aes256Cfb => write!(f, "{}", CIPHER_AES_256_CFB),
            CipherType::Aes256Cfb1 => write!(f, "{}", CIPHER_AES_256_CFB_1),
            CipherType::Aes256Cfb8 => write!(f, "{}", CIPHER_AES_256_CFB_8),
            CipherType::Aes256Cfb128 => write!(f, "{}", CIPHER_AES_256_CFB_128),

            CipherType::Rc4 => write!(f, "{}", CIPHER_RC4),
            CipherType::Rc4Md5 => write!(f, "{}", CIPHER_RC4_MD5),

            CipherType::ChaCha20 => write!(f, "{}", CIPHER_CHACHA20),
            CipherType::Salsa20 => write!(f, "{}", CIPHER_SALSA20),

            CipherType::Aes128Gcm => write!(f, "{}", CIPHER_AES_128_GCM),
            CipherType::Aes192Gcm => write!(f, "{}", CIPHER_AES_192_GCM),
            CipherType::Aes256Gcm => write!(f, "{}", CIPHER_AES_256_GCM),
        }
    }
}

#[cfg(test)]
mod test_cipher {
    use crypto::{StreamCipher, CipherType, new_stream};
    use crypto::CryptoMode;

    #[test]
    fn test_get_cipher() {
        let key = CipherType::Aes128Cfb.bytes_to_key(b"PassWORD");
        let iv = CipherType::Aes128Cfb.gen_init_vec();
        let mut encryptor = new_stream(CipherType::Aes128Cfb,
                                       &key[0..],
                                       &iv[0..],
                                       CryptoMode::Encrypt);
        let mut decryptor = new_stream(CipherType::Aes128Cfb,
                                       &key[0..],
                                       &iv[0..],
                                       CryptoMode::Decrypt);
        let message = "HELLO WORLD";

        let mut encrypted_msg = Vec::new();
        encryptor.update(message.as_bytes(), &mut encrypted_msg).unwrap();
        let mut decrypted_msg = Vec::new();
        decryptor.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert!(message.as_bytes() == &decrypted_msg[..]);
    }
}
