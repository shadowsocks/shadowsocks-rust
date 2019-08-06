//! Stream ciphers

#[cfg(feature = "openssl")]
use crate::crypto::openssl;
#[cfg(feature = "rc4")]
use crate::crypto::rc4_md5;
#[cfg(feature = "sodium")]
use crate::crypto::sodium;
use crate::crypto::{
    cipher::{CipherCategory, CipherResult, CipherType},
    dummy, table, CryptoMode,
};

use bytes::BufMut;

/// Basic operation of Cipher, which is a Symmetric Cipher.
///
/// The `update` method could be called multiple times, and the `finalize` method will
/// encrypt the last block
pub trait StreamCipher {
    fn update(&mut self, data: &[u8], out: &mut BufMut) -> CipherResult<()>;
    fn finalize(&mut self, out: &mut BufMut) -> CipherResult<()>;
    fn buffer_size(&self, data: &[u8]) -> usize;
}

/// Variant cipher which contains all possible stream ciphers
pub type BoxStreamCipher = Box<dyn StreamCipher + Send + 'static>;

/// Generate a specific Cipher with key and initialize vector
#[allow(unused_variables)]
pub fn new_stream(t: CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> BoxStreamCipher {
    assert!(
        t.category() == CipherCategory::Stream,
        "only allow initializing with stream cipher"
    );

    match t {
        CipherType::Table => Box::new(table::TableCipher::new(key, mode)),
        CipherType::Plain => Box::new(dummy::DummyCipher),

        #[cfg(feature = "sodium")]
        CipherType::ChaCha20 | CipherType::Salsa20 | CipherType::XSalsa20 | CipherType::ChaCha20Ietf => {
            Box::new(sodium::SodiumStreamCipher::new(t, key, iv))
        }

        #[cfg(feature = "rc4")]
        CipherType::Rc4Md5 => Box::new(rc4_md5::Rc4Md5Cipher::new(key, iv, mode)),

        #[cfg(feature = "aes-cfb")]
        CipherType::Aes128Cfb
        | CipherType::Aes128Cfb1
        | CipherType::Aes128Cfb8
        | CipherType::Aes128Cfb128
        | CipherType::Aes192Cfb
        | CipherType::Aes192Cfb1
        | CipherType::Aes192Cfb8
        | CipherType::Aes192Cfb128
        | CipherType::Aes256Cfb
        | CipherType::Aes256Cfb1
        | CipherType::Aes256Cfb8
        | CipherType::Aes256Cfb128 => Box::new(openssl::OpenSSLCipher::new(t, key, iv, mode)),

        #[cfg(feature = "aes-ctr")]
        CipherType::Aes128Ctr | CipherType::Aes192Ctr | CipherType::Aes256Ctr => {
            Box::new(openssl::OpenSSLCipher::new(t, key, iv, mode))
        }

        #[cfg(feature = "camellia-cfb")]
        CipherType::Camellia128Cfb
        | CipherType::Camellia128Cfb1
        | CipherType::Camellia128Cfb8
        | CipherType::Camellia128Cfb128
        | CipherType::Camellia192Cfb
        | CipherType::Camellia192Cfb1
        | CipherType::Camellia192Cfb8
        | CipherType::Camellia192Cfb128
        | CipherType::Camellia256Cfb
        | CipherType::Camellia256Cfb1
        | CipherType::Camellia256Cfb8
        | CipherType::Camellia256Cfb128 => Box::new(openssl::OpenSSLCipher::new(t, key, iv, mode)),

        _ => unreachable!("{} is not a stream cipher", t),
    }
}
