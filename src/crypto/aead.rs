//! Aead Ciphers

use crate::crypto::cipher::{CipherCategory, CipherResult, CipherType};

#[cfg(feature = "ring-aead-ciphers")]
use crate::crypto::ring::RingAeadCipher;
#[cfg(feature = "aes-pmac-siv")]
use crate::crypto::siv::MiscreantCipher;
#[cfg(feature = "sodium")]
use crate::crypto::sodium::SodiumAeadCipher;

use bytes::{Bytes, BytesMut};
use hkdf::Hkdf;
use sha1::Sha1;

/// Encryptor API for AEAD ciphers
pub trait AeadEncryptor {
    /// Encrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() + tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = input.len())  | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]);
}

/// Decryptor API for AEAD ciphers
pub trait AeadDecryptor {
    /// Decrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len() - tag.len()`.
    /// ```plain
    /// +----------------------------------------+-----------------------+
    /// | ENCRYPTED TEXT (length = output.len()) | TAG                   |
    /// +----------------------------------------+-----------------------+
    /// ```
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> CipherResult<()>;
}

/// Variant `AeadDecryptor`
pub type BoxAeadDecryptor = Box<dyn AeadDecryptor + Send + 'static>;

/// Variant `AeadEncryptor`
pub type BoxAeadEncryptor = Box<dyn AeadEncryptor + Send + 'static>;

/// Generate a specific AEAD cipher encryptor
pub fn new_aead_encryptor(t: CipherType, key: &[u8], nonce: &[u8]) -> BoxAeadEncryptor {
    assert!(t.category() == CipherCategory::Aead);

    match t {
        #[cfg(feature = "ring-aead-ciphers")]
        CipherType::Aes128Gcm | CipherType::Aes256Gcm | CipherType::ChaCha20IetfPoly1305 => {
            Box::new(RingAeadCipher::new(t, key, nonce, true))
        }

        #[cfg(feature = "sodium")]
        CipherType::XChaCha20IetfPoly1305 => Box::new(SodiumAeadCipher::new(t, key, nonce)),

        #[cfg(feature = "aes-pmac-siv")]
        CipherType::Aes128PmacSiv | CipherType::Aes256PmacSiv => Box::new(MiscreantCipher::new(t, key, nonce)),

        _ => unreachable!(),
    }
}

/// Generate a specific AEAD cipher decryptor
pub fn new_aead_decryptor(t: CipherType, key: &[u8], nonce: &[u8]) -> BoxAeadDecryptor {
    assert!(t.category() == CipherCategory::Aead);

    match t {
        #[cfg(feature = "ring-aead-ciphers")]
        CipherType::Aes128Gcm | CipherType::Aes256Gcm | CipherType::ChaCha20IetfPoly1305 => {
            Box::new(RingAeadCipher::new(t, key, nonce, false))
        }

        #[cfg(feature = "sodium")]
        CipherType::XChaCha20IetfPoly1305 => Box::new(SodiumAeadCipher::new(t, key, nonce)),

        #[cfg(feature = "aes-pmac-siv")]
        CipherType::Aes128PmacSiv | CipherType::Aes256PmacSiv => Box::new(MiscreantCipher::new(t, key, nonce)),

        _ => unreachable!(),
    }
}

const SUBKEY_INFO: &[u8] = b"ss-subkey";

/// Make Session key
///
/// ## Session key (SIP007)
///
/// AEAD ciphers require a per-session subkey derived from the pre-shared master key using HKDF, and use the subkey
/// to encrypt/decrypt. Essentially it means we are moving from (M+N)-bit (PSK, nonce) pair to
/// (M+N)-bit (HKDF(PSK, salt), nonce) pair. Because HKDF is a PRF, the new construction significantly expands the
/// amount of randomness (from N to at least M where M is much greater than N), thus correcting the previously
/// mentioned design flaw.
///
/// Assuming we already have a user-supplied pre-shared master key PSK.
///
/// Function HKDF_SHA1 is a HKDF constructed using SHA1 hash. Its signature is
///
/// ```plain
/// HKDF_SHA1(secret_key, salt, info)
/// ```
///
/// The "info" string argument allows us to bind the derived subkey to a specific application context.
///
/// For AEAD ciphers, the encryption scheme is:
///
/// 1. Pick a random R-bit salt (R = max(128, len(SK)))
/// 2. Derive subkey SK = HKDF_SHA1(PSK, salt, "ss-subkey")
/// 3. Send salt
/// 4. For each chunk, encrypt and authenticate payload using SK with a counting nonce
///    (starting from 0 and increment by 1 after each use)
/// 5. Send encrypted chunk
pub fn make_skey(t: CipherType, key: &[u8], salt: &[u8]) -> Bytes {
    assert!(t.category() == CipherCategory::Aead);

    let hkdf = Hkdf::<Sha1>::new(Some(salt), key);

    let mut skey = BytesMut::with_capacity(key.len());
    unsafe {
        skey.set_len(key.len());
    }

    hkdf.expand(SUBKEY_INFO, &mut skey).unwrap();

    skey.freeze()
}

/// Increase nonce by 1
///
/// AEAD ciphers requires to increase nonce after encrypt/decrypt every chunk
#[cfg(feature = "sodium")]
pub fn increase_nonce(nonce: &mut [u8]) {
    use libsodium_sys::sodium_increment;

    unsafe {
        sodium_increment(nonce.as_mut_ptr(), nonce.len());
    }
}

/// Increase nonce by 1
///
/// AEAD ciphers requires to increase nonce after encrypt/decrypt every chunk
#[cfg(not(feature = "sodium"))]
pub fn increase_nonce(nonce: &mut [u8]) {
    for i in nonce {
        if std::u8::MAX == *i {
            *i = 0;
        } else {
            *i += 1;
            return;
        }
    }
}
