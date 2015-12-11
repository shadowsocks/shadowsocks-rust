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

//! Cipher defined with Rust binding for libsodium

extern crate libc;

use std::iter::repeat;

use crypto::cipher::{Cipher, CipherType, CipherResult};

const BLOCK_SIZE: usize = 64; // Just for Salsa20 and Chacha20

mod ffi {
    pub use libsodium_ffi::crypto_stream_chacha20_xor_ic;
    pub use libsodium_ffi::crypto_stream_salsa20_xor_ic;
}

pub struct SodiumCipher {
    cipher_type: CipherType,
    key: Vec<u8>,
    iv: Vec<u8>,
    counter: usize,
    buf: Vec<u8>,
}

impl SodiumCipher {
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> SodiumCipher {
        match t {
            CipherType::Salsa20 | CipherType::ChaCha20 => (),
            _ => panic!("Sodium does not support {:?} cipher", t),
        }

        SodiumCipher {
            cipher_type: t,
            key: key.to_vec(),
            iv: iv.to_vec(),
            counter: 0,
            buf: Vec::new(),
        }
    }
}

impl Cipher for SodiumCipher {
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        let padding_len = self.counter % BLOCK_SIZE;
        let pad =
            if padding_len == 0 {
                None
            } else {
                let pad = repeat(0u8).take(padding_len).chain(data.iter().map(|&x| x)).collect::<Vec<u8>>();
                Some(pad)
            };

        let padded_data = match &pad {
            &Some(ref p) => &p[..],
            &None => data,
        };

        if self.buf.len() < padding_len + data.len() {
            self.buf.resize(padding_len + data.len(), 0u8);
        }

        match self.cipher_type {
            CipherType::ChaCha20 => unsafe {
                ffi::crypto_stream_chacha20_xor_ic(self.buf.as_mut_ptr() as *mut libc::c_char, padded_data.as_ptr(),
                                                  (padding_len + data.len()) as libc::c_ulonglong,
                                                  self.iv.as_ptr(),
                                                  (self.counter / BLOCK_SIZE) as libc::uint64_t,
                                                  self.key.as_ptr());
            },
            CipherType::Salsa20 => unsafe {
                ffi::crypto_stream_salsa20_xor_ic(self.buf.as_mut_ptr() as *mut libc::c_char, padded_data.as_ptr(),
                                                (padding_len + data.len()) as libc::c_ulonglong,
                                                self.iv.as_ptr(),
                                                (self.counter / BLOCK_SIZE) as libc::uint64_t,
                                                self.key.as_ptr());
            },
            _ => unreachable!(),
        }

        self.counter += data.len();

        out.extend(&self.buf[padding_len..padding_len + data.len()]);

        Ok(())
    }

    fn finalize(&mut self, _: &mut Vec<u8>) -> CipherResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test_sodium {
    use crypto::cipher::{Cipher, CipherType};
    use crypto::sodium::SodiumCipher;

    #[test]
    fn test_sodium_cipher() {
        let ct = CipherType::ChaCha20;

        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::new();
        enc.update(message, &mut encrypted_msg).unwrap();

        let mut dec = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::new();
        dec.update(&encrypted_msg[0..], &mut decrypted_msg).unwrap();

        assert_eq!(message, &decrypted_msg[..]);
    }
}
