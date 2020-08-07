//! Crypto methods for shadowsocks

pub use self::{
    aead::{new_aead_decryptor, new_aead_encryptor, AeadDecryptor, AeadEncryptor, BoxAeadDecryptor, BoxAeadEncryptor},
    cipher::{CipherCategory, CipherResult, CipherType},
    stream::{new_stream, BoxStreamCipher, StreamCipher},
};
#[cfg(feature = "openssl")]
use ::openssl::symm;

pub mod aead;
pub mod cipher;
pub mod dummy;
#[cfg(feature = "openssl")]
pub mod openssl;
#[cfg(feature = "rc4")]
pub mod rc4_md5;
#[cfg(feature = "ring-aead-ciphers")]
pub mod ring;
#[cfg(feature = "aes-pmac-siv")]
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

#[cfg(feature = "openssl")]
impl std::convert::From<CryptoMode> for symm::Mode {
    fn from(m: CryptoMode) -> symm::Mode {
        match m {
            CryptoMode::Encrypt => symm::Mode::Encrypt,
            CryptoMode::Decrypt => symm::Mode::Decrypt,
        }
    }
}
