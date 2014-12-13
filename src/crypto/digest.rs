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

use crypto::openssl;

pub trait Digest {
    fn update(&mut self, data: &[u8]);
    fn digest(&mut self) -> Vec<u8>;
}

#[deriving(Clone, Copy)]
pub enum DigestType {
    Md5,
    Sha1,
    Sha,
}

pub enum DigestVariant {
    OpenSSLDigest(openssl::OpenSSLDigest)
}

impl Digest for DigestVariant {
    fn update(&mut self, data: &[u8]) {
        match *self {
            DigestVariant::OpenSSLDigest(ref mut d) => d.update(data),
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        match *self {
            DigestVariant::OpenSSLDigest(ref mut d) => d.digest()
        }
    }
}

pub fn with_type(t: DigestType) -> DigestVariant {
    match t {
        DigestType::Md5 | DigestType::Sha1 | DigestType::Sha =>
            DigestVariant::OpenSSLDigest(openssl::OpenSSLDigest::new(t)),
    }
}
