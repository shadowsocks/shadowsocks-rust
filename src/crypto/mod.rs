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

//! Crypto methods for shadowsocks


use std::convert::From;

use openssl::symm;

pub use self::cipher::{CipherType, StreamCipher, StreamCipherVariant, CipherResult};

pub mod cipher;
pub mod openssl;
pub mod digest;
pub mod table;
pub mod rc4_md5;
pub mod crypto;
pub mod dummy;

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
