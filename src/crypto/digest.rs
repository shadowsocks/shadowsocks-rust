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

//! Message digest algorithm

use rust_crypto::md5::Md5;
use rust_crypto::sha1::Sha1;

/// Digest trait
pub trait Digest: Send {
    /// Update data
    fn update(&mut self, data: &[u8]);

    /// Generates digest
    fn digest(&mut self, buf: &mut Vec<u8>);

    /// Length of digest
    fn digest_len(&self) -> usize;

    /// Reset digest
    fn reset(&mut self);
}

/// Type of defined digests
#[derive(Clone, Copy)]
pub enum DigestType {
    Md5,
    Sha1,
    Sha,
}

/// Create digest with type
pub fn with_type(t: DigestType) -> DigestVariant {
    match t {
        DigestType::Md5 => DigestVariant::Md5(Md5::new()),
        DigestType::Sha1 | DigestType::Sha => DigestVariant::Sha1(Sha1::new()),
    }
}

/// Variant of supported digest
pub enum DigestVariant {
    Md5(Md5),
    Sha1(Sha1),
}

impl Digest for DigestVariant {
    fn update(&mut self, data: &[u8]) {
        use rust_crypto::digest::Digest;

        match *self {
            DigestVariant::Md5(ref mut d) => d.input(data),
            DigestVariant::Sha1(ref mut d) => d.input(data),
        }
    }

    fn digest(&mut self, buf: &mut Vec<u8>) {
        use rust_crypto::digest::Digest;

        let output_bytes = match *self {
            DigestVariant::Md5(ref d) => d.output_bytes(),
            DigestVariant::Sha1(ref d) => d.output_bytes(),
        };

        let orig_len = buf.len();
        buf.resize(orig_len + output_bytes, 0);
        match *self {
            DigestVariant::Md5(ref mut d) => d.result(&mut buf[orig_len..]),
            DigestVariant::Sha1(ref mut d) => d.result(&mut buf[orig_len..]),
        }
    }

    fn digest_len(&self) -> usize {
        use rust_crypto::digest::Digest;

        match *self {
            DigestVariant::Md5(ref d) => d.output_bytes(),
            DigestVariant::Sha1(ref d) => d.output_bytes(),
        }
    }

    fn reset(&mut self) {
        use rust_crypto::digest::Digest;

        match *self {
            DigestVariant::Md5(ref mut d) => d.reset(),
            DigestVariant::Sha1(ref mut d) => d.reset(),
        }
    }
}