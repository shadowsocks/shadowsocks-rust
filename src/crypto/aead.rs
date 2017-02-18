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

//! Aead Ciphers

use crypto::cipher::{CipherType, CipherCategory, CipherResult};

use crypto::crypto::CryptoAeadCrypto;

use rust_crypto::hkdf::{hkdf_expand, hkdf_extract};
use rust_crypto::sha1::Sha1;
use rust_crypto::digest::Digest;

/// Encryptor API for AEAD ciphers
pub trait AeadEncryptor {
    /// Encrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len()`.
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]);
}

/// Decryptor API for AEAD ciphers
pub trait AeadDecryptor {
    /// Decrypt `input` to `output` with `tag`. `output.len()` should equals to `input.len()`.
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> CipherResult<()>;
}

/// Generate a specific AEAD cipher encryptor
pub fn new_aead_encryptor(t: CipherType, key: &[u8], nounce: &[u8]) -> Box<AeadEncryptor> {
    assert!(t.category() == CipherCategory::Aead);

    match t {
        CipherType::Aes128Gcm |
        CipherType::Aes192Gcm |
        CipherType::Aes256Gcm => Box::new(CryptoAeadCrypto::new(t, key, nounce)),

        _ => unreachable!(),
    }
}

/// Generate a specific AEAD cipher decryptor
pub fn new_aead_decryptor(t: CipherType, key: &[u8], nounce: &[u8]) -> Box<AeadDecryptor> {
    assert!(t.category() == CipherCategory::Aead);

    match t {
        CipherType::Aes128Gcm |
        CipherType::Aes192Gcm |
        CipherType::Aes256Gcm => Box::new(CryptoAeadCrypto::new(t, key, nounce)),

        _ => unreachable!(),
    }
}

const SUBKEY_INFO: &'static [u8] = b"ss-subkey";

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
/// 4. For each chunk, encrypt and authenticate payload using SK with a counting nonce (starting from 0 and increment by 1 after each use)
/// 5. Send encrypted chunk
pub fn make_skey(t: CipherType, key: &[u8], salt: &[u8]) -> Vec<u8> {
    assert!(t.category() == CipherCategory::Aead);

    let sha1 = Sha1::new();
    let output_bytes = sha1.output_bytes();

    let mut prk = vec![0u8; output_bytes];
    hkdf_extract(sha1, salt, key, &mut prk);

    let mut skey = vec![0u8; key.len()];
    hkdf_expand(Sha1::new(), &prk, SUBKEY_INFO, &mut skey);

    skey
}

/// Increase nonce by 1
///
/// AEAD ciphers requires to increase nonce after encrypt/decrypt every chunk
pub fn increase_nonce(nonce: &mut [u8]) {
    let mut adding = true;
    for v in nonce.iter_mut() {
        if !adding {
            break;
        }

        let (r, overflow) = v.overflowing_add(1);
        *v = r;
        adding = overflow;
    }
}