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

use std::str::FromStr;
use std::fmt::{self, Debug, Display};
use std::io;
use rand::{self, Rng};
use std::convert::From;

use crypto::openssl;
use crypto::table;
use crypto::CryptoMode;
use crypto::rc4_md5;
use crypto::crypto::CryptoCipher;

use crypto::digest::{self, DigestType};

use openssl::crypto::symm;

/// Basic operation of Cipher, which is a Symmetric Cipher.
///
/// The `update` method could be called multiple times, and the `finalize` method will
/// encrypt the last block
pub trait Cipher {
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()>;
    fn finalize(&mut self, out: &mut Vec<u8>) -> CipherResult<()>;
}

pub type CipherResult<T> = Result<T, Error>;

pub enum Error {
    UnknownCipherType,
    OpenSSLError(::openssl::error::ErrorStack),
    IoError(io::Error),
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            &Error::OpenSSLError(ref err) => write!(f, "{:?}", err),
            &Error::IoError(ref err) => write!(f, "{:?}", err),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            &Error::OpenSSLError(ref err) => write!(f, "{}", err),
            &Error::IoError(ref err) => write!(f, "{}", err),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::UnknownCipherType => io::Error::new(io::ErrorKind::Other, "Unknown Cipher type"),
            Error::OpenSSLError(err) => From::from(err),
            Error::IoError(err) => err,
        }
    }
}

impl From<::openssl::error::ErrorStack> for Error {
    fn from(e: ::openssl::error::ErrorStack) -> Error {
        Error::OpenSSLError(e)
    }
}

#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_128_CFB: &'static str = "aes-128-cfb";
#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_128_CFB_1: &'static str = "aes-128-cfb1";
#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_128_CFB_8: &'static str = "aes-128-cfb8";
#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_128_CFB_128: &'static str = "aes-128-cfb128";

#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_256_CFB: &'static str = "aes-256-cfb";
#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_256_CFB_1: &'static str = "aes-256-cfb1";
#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_256_CFB_8: &'static str = "aes-256-cfb8";
#[cfg(feature = "cipher-aes-cfb")]
const CIPHER_AES_256_CFB_128: &'static str = "aes-256-cfb128";

#[cfg(feature = "cipher-rc4")]
const CIPHER_RC4: &'static str = "rc4";
#[cfg(feature = "cipher-rc4")]
const CIPHER_RC4_MD5: &'static str = "rc4-md5";

const CIPHER_TABLE: &'static str = "table";

#[cfg(feature = "cipher-chacha20")]
const CIPHER_CHACHA20: &'static str = "chacha20";
#[cfg(feature = "cipher-salsa20")]
const CIPHER_SALSA20: &'static str = "salsa20";

#[derive(Clone, Debug, Copy)]
pub enum CipherType {
    Table,

    #[cfg(feature = "cipher-aes-cfb")]
    Aes128Cfb,
    #[cfg(feature = "cipher-aes-cfb")]
    Aes128Cfb1,
    #[cfg(feature = "cipher-aes-cfb")]
    Aes128Cfb8,
    #[cfg(feature = "cipher-aes-cfb")]
    Aes128Cfb128,

    #[cfg(feature = "cipher-aes-cfb")]
    Aes256Cfb,
    #[cfg(feature = "cipher-aes-cfb")]
    Aes256Cfb1,
    #[cfg(feature = "cipher-aes-cfb")]
    Aes256Cfb8,
    #[cfg(feature = "cipher-aes-cfb")]
    Aes256Cfb128,

    #[cfg(feature = "cipher-rc4")]
    Rc4,
    #[cfg(feature = "cipher-rc4")]
    Rc4Md5,

    #[cfg(feature = "cipher-chacha20")]
    ChaCha20,
    #[cfg(feature = "cipher-salsa20")]
    Salsa20,
}

impl CipherType {
    pub fn block_size(&self) -> usize {
        match *self {
            CipherType::Table => 0,

            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb => symm::Type::AES_128_CFB128.block_size(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb1 => symm::Type::AES_128_CFB1.block_size(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb8 => symm::Type::AES_128_CFB8.block_size(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb128 => symm::Type::AES_128_CFB128.block_size(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb => symm::Type::AES_256_CFB128.block_size(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb1 => symm::Type::AES_256_CFB1.block_size(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb8 => symm::Type::AES_256_CFB8.block_size(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb128 => symm::Type::AES_256_CFB128.block_size(),

            #[cfg(feature = "cipher-rc4")] CipherType::Rc4 => symm::Type::RC4_128.block_size(),
            #[cfg(feature = "cipher-rc4")] CipherType::Rc4Md5 => symm::Type::RC4_128.block_size(),

            #[cfg(feature = "cipher-chacha20")] CipherType::ChaCha20 => 8,
            #[cfg(feature = "cipher-salsa20")] CipherType::Salsa20 => 8,
        }
    }

    pub fn key_size(&self) -> usize {
        match *self {
            CipherType::Table => 0,

            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb => symm::Type::AES_128_CFB128.key_len(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb1 => symm::Type::AES_128_CFB1.key_len(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb8 => symm::Type::AES_128_CFB8.key_len(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb128 => symm::Type::AES_128_CFB128.key_len(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb => symm::Type::AES_256_CFB128.key_len(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb1 => symm::Type::AES_256_CFB1.key_len(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb8 => symm::Type::AES_256_CFB8.key_len(),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb128 => symm::Type::AES_256_CFB128.key_len(),

            #[cfg(feature = "cipher-rc4")] CipherType::Rc4 => symm::Type::RC4_128.key_len(),
            #[cfg(feature = "cipher-rc4")] CipherType::Rc4Md5 => symm::Type::RC4_128.key_len(),

            #[cfg(feature = "cipher-chacha20")] CipherType::ChaCha20 => 32,
            #[cfg(feature = "cipher-salsa20")] CipherType::Salsa20 => 32,
        }
    }

    pub fn bytes_to_key(&self, key: &[u8]) -> Vec<u8> {
        let iv_len = self.block_size();
        let key_len = self.key_size();

        let mut m: Vec<Vec<u8>> = Vec::with_capacity((key_len + iv_len) / DigestType::Md5.digest_len() + 1);
        let mut i = 0;
        while m.len() * DigestType::Md5.digest_len() < (key_len + iv_len) {
            let mut md5 = digest::with_type(DigestType::Md5);
            if i > 0 {
                let mut vkey = m[i - 1].clone();
                vkey.extend_from_slice(key);
                md5.update(&vkey[..]);
            } else {
                md5.update(key);
            }

            m.push(md5.digest());
            i += 1
        }

        let whole = m.iter().fold(Vec::new(), |mut a, b| {
            a.extend_from_slice(b);
            a
        });
        let key = whole[0..key_len].to_vec();
        key
    }

    pub fn iv_size(&self) -> usize {
        match *self {
            CipherType::Table => 0,

            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb => symm::Type::AES_128_CFB128.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb1 => symm::Type::AES_128_CFB1.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb8 => symm::Type::AES_128_CFB8.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb128 => symm::Type::AES_128_CFB128.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb => symm::Type::AES_256_CFB128.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb1 => symm::Type::AES_256_CFB1.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb8 => symm::Type::AES_256_CFB8.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb128 => symm::Type::AES_256_CFB128.iv_len().unwrap_or(0),

            #[cfg(feature = "cipher-rc4")] CipherType::Rc4 => symm::Type::RC4_128.iv_len().unwrap_or(0),
            #[cfg(feature = "cipher-rc4")] CipherType::Rc4Md5 => symm::Type::RC4_128.iv_len().unwrap_or(0),

            #[cfg(feature = "cipher-chacha20")] CipherType::ChaCha20 => 8,
            #[cfg(feature = "cipher-salsa20")] CipherType::Salsa20 => 8,
        }
    }

    pub fn gen_init_vec(&self) -> Vec<u8> {
        let iv_len = self.iv_size();
        let mut iv = Vec::with_capacity(iv_len);
        unsafe {
            iv.set_len(iv_len);
        }
        rand::thread_rng().fill_bytes(iv.as_mut_slice());

        iv
    }
}

impl FromStr for CipherType {
    type Err = Error;
    fn from_str(s: &str) -> Result<CipherType, Error> {
        match s {
            CIPHER_TABLE | "" => Ok(CipherType::Table),
            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_128_CFB => Ok(CipherType::Aes128Cfb),
            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_128_CFB_1 => Ok(CipherType::Aes128Cfb1),
            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_128_CFB_8 => Ok(CipherType::Aes128Cfb8),
            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_128_CFB_128 => Ok(CipherType::Aes128Cfb128),

            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_256_CFB => Ok(CipherType::Aes256Cfb),
            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_256_CFB_1 => Ok(CipherType::Aes256Cfb1),
            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_256_CFB_8 => Ok(CipherType::Aes256Cfb8),
            #[cfg(feature = "cipher-aes-cfb")]
            CIPHER_AES_256_CFB_128 => Ok(CipherType::Aes256Cfb128),

            #[cfg(feature = "cipher-rc4")]
            CIPHER_RC4 => Ok(CipherType::Rc4),
            #[cfg(feature = "cipher-rc4")]
            CIPHER_RC4_MD5 => Ok(CipherType::Rc4Md5),

            #[cfg(feature = "cipher-chacha20")]
            CIPHER_CHACHA20 => Ok(CipherType::ChaCha20),
            #[cfg(feature = "cipher-salsa20")]
            CIPHER_SALSA20 => Ok(CipherType::Salsa20),

            _ => Err(Error::UnknownCipherType),
        }
    }
}

impl Display for CipherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherType::Table => write!(f, "{}", CIPHER_TABLE),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb => write!(f, "{}", CIPHER_AES_128_CFB),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb1 => write!(f, "{}", CIPHER_AES_128_CFB_1),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb8 => write!(f, "{}", CIPHER_AES_128_CFB_8),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes128Cfb128 => write!(f, "{}", CIPHER_AES_128_CFB_128),

            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb => write!(f, "{}", CIPHER_AES_256_CFB),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb1 => write!(f, "{}", CIPHER_AES_256_CFB_1),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb8 => write!(f, "{}", CIPHER_AES_256_CFB_8),
            #[cfg(feature = "cipher-aes-cfb")]
            CipherType::Aes256Cfb128 => write!(f, "{}", CIPHER_AES_256_CFB_128),

            #[cfg(feature = "cipher-rc4")]
            CipherType::Rc4 => write!(f, "{}", CIPHER_RC4),
            #[cfg(feature = "cipher-rc4")]
            CipherType::Rc4Md5 => write!(f, "{}", CIPHER_RC4_MD5),

            #[cfg(feature = "cipher-chacha20")]
            CipherType::ChaCha20 => write!(f, "{}", CIPHER_CHACHA20),
            #[cfg(feature = "cipher-salsa20")]
            CipherType::Salsa20 => write!(f, "{}", CIPHER_SALSA20),
        }
    }
}

macro_rules! define_ciphers {
    ($($name:ident => $cipher:ty,)+) => {
        pub enum CipherVariant {
            $(
                $name($cipher),
            )+
        }

        impl CipherVariant {
            pub fn new<C>(cipher: C) -> CipherVariant
                where CipherVariant: From<C>
            {
                From::from(cipher)
            }
        }

        impl Cipher for CipherVariant {
            fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
                match *self {
                    $(
                        CipherVariant::$name(ref mut cipher) => cipher.update(data, out),
                    )+
                }
            }

            fn finalize(&mut self, out: &mut Vec<u8>) -> CipherResult<()> {
                match *self {
                    $(
                        CipherVariant::$name(ref mut cipher) => cipher.finalize(out),
                    )+
                }
            }
        }

        $(
            impl From<$cipher> for CipherVariant {
                fn from(cipher: $cipher) -> CipherVariant {
                    CipherVariant::$name(cipher)
                }
            }
        )+
    }
}

define_ciphers! {
    TableCipher => table::TableCipher,
    Rc4Md5Cipher => rc4_md5::Rc4Md5Cipher,
    OpenSSLCipher => openssl::OpenSSLCipher,
    CryptoCipher => CryptoCipher,
}

/// Generate a specific Cipher with key and initialize vector
pub fn with_type(t: CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> CipherVariant {
    match t {
        CipherType::Table => CipherVariant::new(table::TableCipher::new(key, mode)),

        #[cfg(feature = "cipher-chacha20")]
        CipherType::ChaCha20 => CipherVariant::new(CryptoCipher::new(t, key, iv)),
        #[cfg(feature = "cipher-salsa20")]
        CipherType::Salsa20 => CipherVariant::new(CryptoCipher::new(t, key, iv)),

        #[cfg(feature = "cipher-rc4")]
        CipherType::Rc4Md5 => CipherVariant::new(rc4_md5::Rc4Md5Cipher::new(key, iv, mode)),

        _ => CipherVariant::new(openssl::OpenSSLCipher::new(t, key, iv, mode)),
    }
}

#[cfg(test)]
mod test_cipher {
    use crypto::cipher::{Cipher, CipherType, with_type};
    use crypto::CryptoMode;

    #[test]
    fn test_get_cipher() {
        let key = CipherType::Aes128Cfb.bytes_to_key(b"PassWORD");
        let iv = CipherType::Aes128Cfb.gen_init_vec();
        let mut encryptor = with_type(CipherType::Aes128Cfb,
                                      &key[0..],
                                      &iv[0..],
                                      CryptoMode::Encrypt);
        let mut decryptor = with_type(CipherType::Aes128Cfb,
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
