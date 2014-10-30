// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

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

use crypto::openssl;

/// The trait for basic cipher methods
pub trait Cipher {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_128_CFB: &'static str = "aes-128-cfb";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_128_CFB_1: &'static str = "aes-128-cfb1";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_128_CFB_8: &'static str = "aes-128-cfb8";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_128_CFB_128: &'static str = "aes-128-cfb128";

#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_192_CFB: &'static str = "aes-192-cfb";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_192_CFB_1: &'static str = "aes-192-cfb1";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_192_CFB_8: &'static str = "aes-192-cfb8";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_192_CFB_128: &'static str = "aes-192-cfb128";

#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_256_CFB: &'static str = "aes-256-cfb";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_256_CFB_1: &'static str = "aes-256-cfb1";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_256_CFB_8: &'static str = "aes-256-cfb8";
#[cfg(feature = "cipher-aes-cfb")]
pub const CIPHER_AES_256_CFB_128: &'static str = "aes-256-cfb128";

#[cfg(feature = "cipher-aes-ofb")]
pub const CIPHER_AES_128_OFB: &'static str = "aes-128-ofb";
#[cfg(feature = "cipher-aes-ofb")]
pub const CIPHER_AES_192_OFB: &'static str = "aes-192-ofb";
#[cfg(feature = "cipher-aes-ofb")]
pub const CIPHER_AES_256_OFB: &'static str = "aes-256-ofb";

#[cfg(feature = "cipher-aes-ctr")]
pub const CIPHER_AES_128_CTR: &'static str = "aes-128-ctr";
#[cfg(feature = "cipher-aes-ctr")]
pub const CIPHER_AES_192_CTR: &'static str = "aes-192-ctr";
#[cfg(feature = "cipher-aes-ctr")]
pub const CIPHER_AES_256_CTR: &'static str = "aes-256-ctr";

#[cfg(feature = "cipher-bf-cfb")]
pub const CIPHER_BF_CFB: &'static str = "bf-cfb";

#[cfg(feature = "cipher-camellia-cfb")]
pub const CIPHER_CAMELLIA_128_CFB: &'static str = "camellia-128-cfb";
#[cfg(feature = "cipher-camellia-cfb")]
pub const CIPHER_CAMELLIA_192_CFB: &'static str = "camellia-192-cfb";
#[cfg(feature = "cipher-camellia-cfb")]
pub const CIPHER_CAMELLIA_256_CFB: &'static str = "camellia-256-cfb";

#[cfg(feature = "cipher-cast5-cfb")]
pub const CIPHER_CAST5_CFB: &'static str = "cast5-cfb";
#[cfg(feature = "cipher-des-cfb")]
pub const CIPHER_DES_CFB: &'static str = "des-cfb";
#[cfg(feature = "cipher-idea-cfb")]
pub const CIPHER_IDEA_CFB: &'static str = "idea-cfb";
#[cfg(feature = "cipher-rc2-cfb")]
pub const CIPHER_RC2_CFB: &'static str = "rc2-cfb";
#[cfg(feature = "cipher-rc4")]
pub const CIPHER_RC4: &'static str = "rc4";
#[cfg(feature = "cipher-rc4")]
pub const CIPHER_RC4_MD5: &'static str = "rc4-md5";
#[cfg(feature = "cipher-seed-cfb")]
pub const CIPHER_SEED_CFB: &'static str = "seed-cfb";

#[deriving(Clone, Show)]
pub enum CipherType {
    Unknown,

    #[cfg(feature = "cipher-aes-cfb")] Aes128Cfb,
    #[cfg(feature = "cipher-aes-cfb")] Aes128Cfb1,
    #[cfg(feature = "cipher-aes-cfb")] Aes128Cfb8,
    #[cfg(feature = "cipher-aes-cfb")] Aes128Cfb128,

    #[cfg(feature = "cipher-aes-cfb")] Aes192Cfb,
    #[cfg(feature = "cipher-aes-cfb")] Aes192Cfb1,
    #[cfg(feature = "cipher-aes-cfb")] Aes192Cfb8,
    #[cfg(feature = "cipher-aes-cfb")] Aes192Cfb128,

    #[cfg(feature = "cipher-aes-cfb")] Aes256Cfb,
    #[cfg(feature = "cipher-aes-cfb")] Aes256Cfb1,
    #[cfg(feature = "cipher-aes-cfb")] Aes256Cfb8,
    #[cfg(feature = "cipher-aes-cfb")] Aes256Cfb128,

    #[cfg(feature = "cipher-aes-ofb")] Aes128Ofb,
    #[cfg(feature = "cipher-aes-ofb")] Aes192Ofb,
    #[cfg(feature = "cipher-aes-ofb")] Aes256Ofb,

    #[cfg(feature = "cipher-aes-ctr")] Aes128Ctr,
    #[cfg(feature = "cipher-aes-ctr")] Aes192Ctr,
    #[cfg(feature = "cipher-aes-ctr")] Aes256Ctr,

    #[cfg(feature = "cipher-bf-cfb")] BfCfb,

    #[cfg(feature = "cipher-camellia-cfb")] Camellia128Cfb,
    #[cfg(feature = "cipher-camellia-cfb")] Camellia192Cfb,
    #[cfg(feature = "cipher-camellia-cfb")] Camellia256Cfb,

    #[cfg(feature = "cipher-cast5-cfb")] Cast5Cfb,
    #[cfg(feature = "cipher-des-cfb")] DesCfb,
    #[cfg(feature = "cipher-idea-cfb")] IdeaCfb,
    #[cfg(feature = "cipher-rc2-cfb")] Rc2Cfb,
    #[cfg(feature = "cipher-rc4")] Rc4,
    #[cfg(feature = "cipher-rc4")] Rc4Md5,
    #[cfg(feature = "cipher-seed-cfb")] SeedCfb,
}

#[deriving(Clone)]
pub enum CipherVariant {
    OpenSSLCrypto(openssl::OpenSSLCipher),
}

impl Cipher for CipherVariant {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        match *self {
            OpenSSLCrypto(ref mut c) => c.encrypt(data),
        }
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        match *self {
            OpenSSLCrypto(ref mut c) => c.decrypt(data),
        }
    }
}

/// Get a Cipher with the provided name
///
/// If the cipher name `method` is not defined or enabled, this function should return `None`,
/// otherwise, it will generate a new cipher with the provided `key`.
///
/// ```rust
/// use shadowsocks::crypto::cipher;
/// use shadowsocks::crypto::cipher::Cipher;
///
/// let mut cipher = match cipher::with_name("aes-256-cfb", "cipher_password".as_bytes()) {
///     Some(cipher) => { cipher },
///     None => { fail!("Undefined cipher!") },
/// };
///
/// let message = "test message".as_bytes();
/// let encrypted_message = cipher.encrypt(message);
/// let decrypted_message = cipher.decrypt(encrypted_message.as_slice());
///
/// assert!(decrypted_message.as_slice() == message);
/// ```
///
/// *Note: The cipher have to be mutable if you want to use it for encrypting and decrypting.*
pub fn with_name(method: &str, key: &[u8]) -> Option<CipherVariant> {
    match method {
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_128_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes128Cfb, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_128_CFB_1 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes128Cfb1, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_128_CFB_8 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes128Cfb8, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_128_CFB_128 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes128Cfb128, key))),

        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_192_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes192Cfb, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_192_CFB_1 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes192Cfb1, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_192_CFB_8 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes192Cfb8, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_192_CFB_128 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes192Cfb128, key))),

        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_256_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes256Cfb, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_256_CFB_1 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes256Cfb1, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_256_CFB_8 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes256Cfb8, key))),
        #[cfg(feature = "cipher-aes-cfb")]
        CIPHER_AES_256_CFB_128 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes256Cfb128, key))),

        #[cfg(feature = "cipher-aes-ofb")]
        CIPHER_AES_128_OFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes128Ofb, key))),
        #[cfg(feature = "cipher-aes-ofb")]
        CIPHER_AES_192_OFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes192Ofb, key))),
        #[cfg(feature = "cipher-aes-ofb")]
        CIPHER_AES_256_OFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes256Ofb, key))),

        #[cfg(feature = "cipher-aes-ctr")]
        CIPHER_AES_128_CTR => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes128Ctr, key))),
        #[cfg(feature = "cipher-aes-ctr")]
        CIPHER_AES_192_CTR => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes192Ctr, key))),
        #[cfg(feature = "cipher-aes-ctr")]
        CIPHER_AES_256_CTR => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Aes256Ctr, key))),

        #[cfg(feature = "cipher-bf-cfb")]
        CIPHER_BF_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(BfCfb, key))),

        #[cfg(feature = "cipher-camellia-cfb")]
        CIPHER_CAMELLIA_128_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Camellia128Cfb, key))),
        #[cfg(feature = "cipher-camellia-cfb")]
        CIPHER_CAMELLIA_192_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Camellia192Cfb, key))),
        #[cfg(feature = "cipher-camellia-cfb")]
        CIPHER_CAMELLIA_256_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Camellia256Cfb, key))),

        #[cfg(feature = "cipher-cast5-cfb")]
        CIPHER_CAST5_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Cast5Cfb, key))),
        #[cfg(feature = "cipher-des-cfb")]
        CIPHER_DES_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(DesCfb, key))),
        #[cfg(feature = "cipher-idea-cfb")]
        CIPHER_IDEA_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(IdeaCfb, key))),
        #[cfg(feature = "cipher-rc2-cfb")]
        CIPHER_RC2_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Rc2Cfb, key))),
        #[cfg(feature = "cipher-rc4")]
        CIPHER_RC4 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Rc4, key))),
        #[cfg(feature = "cipher-rc4")]
        CIPHER_RC4_MD5 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(Rc4Md5, key))),
        #[cfg(feature = "cipher-seed-cfb")]
        CIPHER_SEED_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(SeedCfb, key))),

        _ => None
    }
}

#[test]
fn test_get_cipher() {
    let key = "PASSWORD";
    let mut c = with_name(CIPHER_AES_128_CFB, key.as_bytes()).unwrap();
    let message = "HELLO WORLD";

    let encrypted_msg = c.encrypt(message.as_bytes());
    let decrypted_msg = c.decrypt(encrypted_msg.as_slice());

    assert!(message.as_bytes() == decrypted_msg.as_slice());
}
