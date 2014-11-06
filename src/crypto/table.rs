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

//! This module implements the `table` cipher for fallback compatibility

use std::vec::Vec;
use std::io::BufReader;
use std::cmp::PartialOrd;

use crypto::cipher::Cipher;
use crypto::digest;
use crypto::digest::Digest;
use crypto::digest::Md5;

const TABLE_SIZE: uint = 256u;

#[deriving(Clone)]
pub struct TableCipher {
    enc: Vec<u8>,
    dec: Vec<u8>,
}

impl TableCipher {
    pub fn new(key: &[u8]) -> TableCipher {
        let mut md5_digest = digest::with_type(Md5);
        md5_digest.update(key);
        let key_digest = md5_digest.digest();

        let mut bufr = BufReader::new(key_digest.as_slice());
        let a = bufr.read_le_u64().unwrap();
        let mut table = Vec::<u64>::from_fn(TABLE_SIZE, |idx| idx as u64);

        for i in range(1, 1024) {
            table.as_mut_slice().sort_by(|x, y| {
                let sub = (a % (*x + i) - a % (*y + i)) as i64;

                sub.partial_cmp(&0i64).unwrap()
            })
        }

        let enc = Vec::from_fn(table.len(), |idx| table[idx] as u8);
        let mut dec = Vec::from_elem(enc.len(), 0u8);

        for idx in range(0, enc.len()) {
            dec[enc[idx] as uint] = idx as u8;
        }

        TableCipher {
            enc: enc,
            dec: dec,
        }
    }
}

impl Cipher for TableCipher {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        for d in data.iter() {
            result.push(self.enc[*d as uint]);
        }
        result
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        for d in data.iter() {
            result.push(self.dec[*d as uint]);
        }
        result
    }
}

#[test]
fn test_table_cipher() {
    let message = "hello world";
    let key = "keykeykk";

    let mut cipher = TableCipher::new(key.as_bytes());
    let encrypted_msg = cipher.encrypt(message.as_bytes());
    let decrypted_msg = cipher.decrypt(encrypted_msg.as_slice());

    assert_eq!(decrypted_msg.as_slice(), message.as_bytes());
}
