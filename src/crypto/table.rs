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

use std::io::BufReader;

use crypto::cipher::{Cipher, CipherResult};
use crypto::digest;
use crypto::digest::Digest;
use crypto::digest::DigestType;
use crypto::CryptoMode;

const TABLE_SIZE: usize = 256us;

#[derive(Clone)]
pub struct TableCipher {
    table: Vec<u8>,
}

impl TableCipher {
    pub fn new(key: &[u8], mode: CryptoMode) -> TableCipher {
        let mut md5_digest = digest::with_type(DigestType::Md5);
        md5_digest.update(key);
        let key_digest = md5_digest.digest();

        let mut bufr = BufReader::new(key_digest.as_slice());
        let a = bufr.read_le_u64().unwrap();
        let mut table = range(0, TABLE_SIZE).map(|idx| idx as u64).collect::<Vec<u64>>();

        for i in range(1, 1024) {
            table.as_mut_slice().sort_by(|x, y| {
                (a % (*x + i)).cmp(&(a % (*y + i)))
            })
        }

        // let enc = range(0, TABLE_SIZE).map(|idx| table[idx] as u8).collect::<Vec<u8>>();
        // let mut dec = repeat(0u8).take(enc.len()).collect::<Vec<u8>>();

        // for idx in range(0, enc.len()) {
        //     dec[enc[idx] as usize] = idx as u8;
        // }

        TableCipher {
            table: match mode {
                CryptoMode::Encrypt => table.into_iter().map(|x| x as u8).collect(),
                CryptoMode::Decrypt => {
                    let mut t = Vec::with_capacity(table.len());
                    unsafe { t.set_len(table.len()); }
                    for idx in range(0, table.len()) {
                        t[table[idx] as usize] = idx as u8;
                    }
                    t
                }
            },
        }
    }

    fn process(&mut self, data: &[u8]) -> CipherResult<Vec<u8>> {
        let r = data.iter().map(|d| self.table[*d as usize]).collect();
        Ok(r)
    }
}

impl Cipher for TableCipher {
    fn update(&mut self, data: &[u8]) -> CipherResult<Vec<u8>> {
        self.process(data)
    }

    fn finalize(&mut self) -> CipherResult<Vec<u8>> {
        Ok(Vec::new())
    }
}

#[test]
fn test_table_cipher() {
    let message = "hello world";
    let key = "keykeykk";

    let mut enc = TableCipher::new(key.as_bytes(), CryptoMode::Encrypt);
    let mut dec = TableCipher::new(key.as_bytes(), CryptoMode::Decrypt);
    let encrypted_msg = enc.update(message.as_bytes()).unwrap();
    let decrypted_msg = dec.update(encrypted_msg.as_slice()).unwrap();

    assert_eq!(decrypted_msg.as_slice(), message.as_bytes());
}
