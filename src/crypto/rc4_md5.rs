// The MIT License (MIT)

// Copyright (c) 2014 Y. T. Chung

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

//! Rc4Md5 cipher definition

use crypto::openssl::{OpenSSLCrypto, OpenSSLDigest};
use crypto::cipher::{Cipher, CipherType, CipherResult};
use crypto::digest::{Digest, DigestType};
use crypto::CryptoMode;

/// Rc4Md5 Cipher
pub struct Rc4Md5Cipher {
    crypto: OpenSSLCrypto,
}

impl Rc4Md5Cipher {
    pub fn new(key: &[u8], iv: &[u8], mode: CryptoMode) -> Rc4Md5Cipher {
        let mut md5_digest = OpenSSLDigest::new(DigestType::Md5);
        md5_digest.update(key);
        md5_digest.update(iv);
        let key = md5_digest.digest();

        Rc4Md5Cipher {
            crypto: OpenSSLCrypto::new(CipherType::Rc4, &key[..], b"", mode)
        }
    }
}

impl Cipher for Rc4Md5Cipher {
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        self.crypto.update(data, out)
    }

    fn finalize(&mut self, out: &mut Vec<u8>) -> CipherResult<()> {
        self.crypto.finalize(out)
    }
}

unsafe impl Send for Rc4Md5Cipher {}
