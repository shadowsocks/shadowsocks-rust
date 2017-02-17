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

pub trait AeadEncryptor {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]);
}

pub trait AeadDecryptor {
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