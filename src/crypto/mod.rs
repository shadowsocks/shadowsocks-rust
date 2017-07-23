//! Crypto methods for shadowsocks

use std::convert::From;

use openssl::symm;

pub use self::aead::{AeadDecryptor, AeadEncryptor, BoxAeadDecryptor, BoxAeadEncryptor, new_aead_decryptor,
                     new_aead_encryptor};
pub use self::cipher::{CipherCategory, CipherResult, CipherType};
pub use self::stream::{StreamCipher, StreamCipherVariant, new_stream};

pub mod cipher;
pub mod openssl;
pub mod digest;
pub mod table;
pub mod rc4_md5;
pub mod ring;
pub mod dummy;
pub mod aead;
pub mod stream;

#[cfg(feature = "sodiumoxide")]
pub mod sodium;

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
