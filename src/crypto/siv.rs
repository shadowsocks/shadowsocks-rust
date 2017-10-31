//! Miscreant

use std::{iter, ptr};

use miscreant::{Aes128PmacSiv, Aes256PmacSiv};

use crypto::{AeadDecryptor, AeadEncryptor};
use crypto::{CipherResult, CipherType};
use crypto::aead::{increase_nonce, make_skey};
use crypto::cipher::Error;

use bytes::{BufMut, BytesMut};

use byte_string::ByteStr;



pub enum MiscreantCryptoVariant {
    Aes128(Aes128PmacSiv),
    Aes256(Aes256PmacSiv)
}

pub struct MiscreantCipher {
    cipher: MiscreantCryptoVariant,
    nonce: BytesMut
}

impl MiscreantCipher {
    pub fn new(t: CipherType, key: &[u8], salt: &[u8]) -> Self {
        let nonce_size = t.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        unsafe {
            nonce.set_len(nonce_size);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
        }

        let skey = make_skey(t, key, salt);
        let cipher = Self::new_variant(t, &skey);
        MiscreantCipher { cipher: cipher, nonce: nonce }
    }

    fn new_variant(t: CipherType, key: &[u8]) -> MiscreantCryptoVariant {
        match t {
            CipherType::Aes128PmacSiv => {
                let mut skey = [0; 32];
                skey.copy_from_slice(key);
                MiscreantCryptoVariant::Aes128(Aes128PmacSiv::new(&skey))
            },
            CipherType::Aes256PmacSiv => {
                let mut skey = [0; 64];
                skey.copy_from_slice(key);
                MiscreantCryptoVariant::Aes256(Aes256PmacSiv::new(&skey))
            },
            _ => panic!("unsupported cipher in miscreant {:?}", t),
        }
    }
}

impl AeadEncryptor for MiscreantCipher {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]) {
        let tag_len = tag.len();
        let buf_len = input.len() + tag_len;

        let mut buf = BytesMut::with_capacity(buf_len);
        buf.put_slice(input);
        unsafe {
            buf.set_len(buf_len);
        }

        match self.cipher {
            MiscreantCryptoVariant::Aes128(ref mut cipher) => {
                cipher.seal_in_place(iter::once(&self.nonce), &mut buf);
                output.copy_from_slice(&buf[..input.len()]);
                tag.copy_from_slice(&buf[input.len()..]);
            },
            MiscreantCryptoVariant::Aes256(ref mut cipher) => {
                cipher.seal_in_place(iter::once(&self.nonce), &mut buf);
                output.copy_from_slice(&buf[..input.len()]);
                tag.copy_from_slice(&buf[input.len()..]);
            }
        }

        increase_nonce(&mut self.nonce);
    }
}

impl AeadDecryptor for MiscreantCipher {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> CipherResult<()> {
        let mut buf = BytesMut::with_capacity(input.len() + tag.len());
        buf.put_slice(input);
        buf.put_slice(tag);

        let result = match self.cipher {
            MiscreantCryptoVariant::Aes128(ref mut cipher) =>
                cipher.open_in_place(iter::once(&self.nonce), &mut buf),
            MiscreantCryptoVariant::Aes256(ref mut cipher) =>
                cipher.open_in_place(iter::once(&self.nonce), &mut buf)
        };

        result
            .map(|buf| {
                output.copy_from_slice(buf);
                increase_nonce(&mut self.nonce);
            })
            .map_err(|_| {
                error!("AEAD decrypt failed, nonce={:?}, input={:?}, tag={:?}, err: decrypt failure",
                       ByteStr::new(&self.nonce),
                       ByteStr::new(input),
                       ByteStr::new(tag));
                Error::AeadDecryptFailed
            })
    }
}
