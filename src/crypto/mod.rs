//! Crypto methods for shadowsocks

pub use self::{
    aead::{new_aead_decryptor, new_aead_encryptor, AeadDecryptor, AeadEncryptor, BoxAeadDecryptor, BoxAeadEncryptor},
    cipher::{CipherCategory, CipherResult, CipherType},
    stream::{new_stream, BoxStreamCipher, StreamCipher},
};
use ::openssl::symm;
use std::convert::From;

pub mod aead;
pub mod cipher;
pub mod digest;
pub mod dummy;
pub mod openssl;
#[cfg(feature = "rc4")]
pub mod rc4_md5;
pub mod ring;
#[cfg(feature = "miscreant")]
pub mod siv;
#[cfg(feature = "sodium")]
pub mod sodium;
pub mod stream;
pub mod table;

/// Crypto mode, encrypt or decrypt
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CryptoMode {
    Encrypt,
    Decrypt,
}

impl From<CryptoMode> for symm::Mode {
    fn from(m: CryptoMode) -> symm::Mode {
        match m {
            CryptoMode::Encrypt => symm::Mode::Encrypt,
            CryptoMode::Decrypt => symm::Mode::Decrypt,
        }
    }
}
