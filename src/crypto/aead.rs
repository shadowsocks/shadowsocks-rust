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