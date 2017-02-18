//! This module implements the `table` cipher for fallback compatibility

use std::io::BufReader;

use crypto::{StreamCipher, CipherResult};
use crypto::digest::{self, DigestType, Digest};
use crypto::CryptoMode;

use byteorder::{ReadBytesExt, LittleEndian};

const TABLE_SIZE: usize = 256usize;

/// Table cipher
#[derive(Clone)]
pub struct TableCipher {
    table: Vec<u8>,
}

impl TableCipher {
    pub fn new(key: &[u8], mode: CryptoMode) -> TableCipher {
        let mut md5_digest = digest::with_type(DigestType::Md5);
        md5_digest.update(key);
        let mut key_digest = Vec::new();
        md5_digest.digest(&mut key_digest);

        let mut bufr = BufReader::new(&key_digest[..]);
        let a = bufr.read_u64::<LittleEndian>().unwrap();
        let mut table = (0..TABLE_SIZE).map(|idx| idx as u64).collect::<Vec<u64>>();

        for i in 1..1024 {
            table.as_mut_slice().sort_by(|x, y| (a % (*x + i)).cmp(&(a % (*y + i))))
        }

        TableCipher {
            table: match mode {
                CryptoMode::Encrypt => table.into_iter().map(|x| x as u8).collect(),
                CryptoMode::Decrypt => {
                    let mut t = Vec::with_capacity(table.len());
                    unsafe {
                        t.set_len(table.len());
                    }
                    for (idx, &item) in table.iter().enumerate() {
                        t[item as usize] = idx as u8;
                    }
                    t
                }
            },
        }
    }

    fn process(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        out.reserve(data.len());
        for d in data.iter() {
            out.push(self.table[*d as usize]);
        }
        Ok(())
    }
}

impl StreamCipher for TableCipher {
    fn update(&mut self, data: &[u8], out: &mut Vec<u8>) -> CipherResult<()> {
        self.process(data, out)
    }

    fn finalize(&mut self, _: &mut Vec<u8>) -> CipherResult<()> {
        Ok(())
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
