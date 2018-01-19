//! This module implements the `table` cipher for fallback compatibility

use std::io::Cursor;

use crypto::{CipherResult, StreamCipher};
use crypto::CryptoMode;
use crypto::digest::{self, Digest, DigestType};

use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};

const TABLE_SIZE: usize = 256usize;

/// Table cipher
pub struct TableCipher {
    table: [u8; TABLE_SIZE],
}

impl TableCipher {
    pub fn new(key: &[u8], mode: CryptoMode) -> TableCipher {
        let mut md5_digest = digest::with_type(DigestType::Md5);
        md5_digest.update(key);
        let mut key_digest = BytesMut::with_capacity(md5_digest.digest_len());
        md5_digest.digest(&mut key_digest);

        let mut bufr = Cursor::new(&key_digest[..]);
        let a = bufr.read_u64::<LittleEndian>().unwrap();

        let mut table = [0u64; TABLE_SIZE];
        for i in 0..TABLE_SIZE {
            table[i] = i as u64;
        }

        for i in 1..1024 {
            table.sort_by(|x, y| (a % (*x + i)).cmp(&(a % (*y + i))))
        }

        TableCipher { table: match mode {
                          CryptoMode::Encrypt => {
                              let mut t = [0u8; TABLE_SIZE];
                              for i in 0..TABLE_SIZE {
                                  t[i] = table[i] as u8;
                              }
                              t
                          }
                          CryptoMode::Decrypt => {
                              let mut t = [0u8; TABLE_SIZE];
                              for (idx, &item) in table.iter().enumerate() {
                                  t[item as usize] = idx as u8;
                              }
                              t
                          }
                      }, }
    }

    fn process<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        let mut buf = BytesMut::with_capacity(self.buffer_size(data));
        unsafe {
            buf.set_len(self.buffer_size(data)); // Set length
        }
        for (idx, d) in data.iter().enumerate() {
            buf[idx] = self.table[*d as usize];
        }
        out.put(buf);
        Ok(())
    }
}

impl StreamCipher for TableCipher {
    fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        self.process(data, out)
    }

    fn finalize<B: BufMut>(&mut self, _: &mut B) -> CipherResult<()> {
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}

#[test]
fn test_table_cipher() {
    let message = "hello world";
    let key = "keykeykk";

    let mut enc = TableCipher::new(key.as_bytes(), CryptoMode::Encrypt);
    let mut dec = TableCipher::new(key.as_bytes(), CryptoMode::Decrypt);
    let mut encrypted_msg = Vec::new();
    enc.update(message.as_bytes(), &mut encrypted_msg).unwrap();
    let mut decrypted_msg = Vec::new();
    dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

    assert_eq!(&decrypted_msg[..], message.as_bytes());
}
