//! Crypto methods for shadowsocks

use std::convert::From;

use openssl::symm;

pub use self::cipher::{CipherType, CipherCategory, CipherResult};
pub use self::stream::{StreamCipher, StreamCipherVariant, new_stream};
pub use self::aead::{AeadEncryptor, AeadDecryptor, new_aead_encryptor, new_aead_decryptor};

pub mod cipher;
pub mod openssl;
pub mod digest;
pub mod table;
pub mod rc4_md5;
pub mod crypto;
pub mod dummy;
pub mod aead;
pub mod stream;

/// Crypto mode, encrypt or decrypt
#[derive(Clone, Copy)]
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
