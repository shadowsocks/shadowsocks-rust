// The MIT License (MIT)

// Copyright (c) 2015 Y. T. Chung

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

use std::rand::{self, Rng};

use crypto::cipher::CipherType;
use crypto::digest::{self, Digest, DigestType};
use crypto::openssl::OpenSSLDigest;

/// Equivalent to OpenSSL's EVP_BytesToKey() with count 1
pub fn bytes_to_key(t: CipherType, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let iv_len = t.block_size();
    let key_len = t.key_size();

    let mut m: Vec<Vec<u8>> = Vec::with_capacity((key_len + iv_len) / DigestType::Md5.digest_len() + 1);
    let mut i = 0;
    while m.len() * DigestType::Md5.digest_len() < (key_len + iv_len) {
        let mut md5 = digest::with_type(DigestType::Md5);
        if i > 0 {
            let mut vkey = m[i - 1].clone();
            vkey.push_all(key);
            md5.update(vkey.as_slice());
        } else {
            md5.update(key);
        }

        m.push(md5.digest());
        i += 1
    }

    let whole = m.into_iter().fold(Vec::new(), |mut a, b| { a.push_all(b.as_slice()); a });

    let key = whole[0..key_len].to_vec();
    let mut iv = Vec::with_capacity(iv_len);
    unsafe { iv.set_len(iv_len); }
    rand::thread_rng().fill_bytes(iv.as_mut_slice());

    (key, iv)
}

pub fn convert_rc4_md5_key(key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut md5_digest = OpenSSLDigest::new(DigestType::Md5);
    md5_digest.update(key);
    md5_digest.update(iv);
    md5_digest.digest()
}

#[cfg(test)]
mod test {
    extern crate libc;

    use std::ptr;

    use crypto::openssl::OpenSSLCrypto;
    use crypto::cipher::CipherType;
    use crypto::openssl::OpenSSLDigest;
    use crypto::digest::DigestType;
    use crypto::util::bytes_to_key;

    #[allow(non_camel_case_types)]
    type EVP_CIPHER = *const libc::c_void;
    #[allow(non_camel_case_types)]
    type EVP_MD = *const libc::c_void;

    #[link(name = "crypto")]
    extern {
        fn EVP_BytesToKey(cipher: EVP_CIPHER, md: EVP_MD,
                          salt: *const libc::c_uchar, data: *const libc::c_uchar, datal: libc::c_int,
                          count: libc::c_int, key: *mut libc::c_uchar, iv: *mut libc::c_uchar) -> libc::c_int;
    }

    fn openssl_bytes_to_key(t: CipherType, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cipher = OpenSSLCrypto::get_cipher(t);
        let mut pad_key = Vec::with_capacity(t.key_size());
        let mut pad_iv = Vec::with_capacity(t.block_size());

        unsafe {
            pad_key.set_len(t.key_size());
            pad_iv.set_len(t.block_size());

            EVP_BytesToKey(cipher, OpenSSLDigest::get_md(DigestType::Md5),
                           ptr::null(), key.as_ptr(), key.len() as libc::c_int,
                           1, pad_key.as_mut_ptr(), pad_iv.as_mut_ptr());
        }

        (pad_key, pad_iv)
    }

    #[test]
    fn test_bytes_to_key() {
        let key = b"PASSword";

        let (key1, _) = bytes_to_key(CipherType::Aes256Cfb, key);
        let (key2, _) = openssl_bytes_to_key(CipherType::Aes256Cfb, key);

        assert_eq!(key1, key2);
    }
}
