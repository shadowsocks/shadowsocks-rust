//! Cipher defined with Ring

use std::mem;
use std::ptr;

use ring::aead::{open_in_place, seal_in_place, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, OpeningKey, SealingKey};

use crypto::aead::{increase_nonce, make_skey};
use crypto::cipher::Error;
use crypto::{AeadDecryptor, AeadEncryptor};
use crypto::{CipherResult, CipherType};

use bytes::{BufMut, Bytes, BytesMut};

use byte_string::ByteStr;

/// AEAD ciphers provided by Ring
pub enum RingAeadCryptoVariant {
    Seal(SealingKey, Bytes),
    Open(OpeningKey, Bytes),
}

/// AEAD Cipher context
///
/// According to SIP004, the `nonce` has to incr 1 after each encrypt/decrypt.
pub struct RingAeadCipher {
    cipher: RingAeadCryptoVariant,
    cipher_type: CipherType,
    key: Bytes,
    nonce: BytesMut,
}

impl RingAeadCipher {
    /// Initialize context
    pub fn new(t: CipherType, key: &[u8], salt: &[u8], is_seal: bool) -> RingAeadCipher {
        // TODO: Check if salt is duplicated

        let nonce_size = t.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        unsafe {
            nonce.set_len(nonce_size);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
        }

        let skey = make_skey(t, key, salt);
        let cipher = RingAeadCipher::new_variant(t, &skey, &nonce, is_seal);
        RingAeadCipher { cipher: cipher,
                         cipher_type: t,
                         key: skey,
                         nonce: nonce, }
    }

    fn new_variant(t: CipherType, key: &[u8], nonce: &[u8], is_seal: bool) -> RingAeadCryptoVariant {
        macro_rules! seal_or_open {
            ($item:ident, $key:ident, $crypt:ident) => {
                RingAeadCryptoVariant::$item($key::new(&$crypt, key).unwrap(), Bytes::from(nonce))
            };
            ($crypt:ident) => {
                if is_seal {
                    seal_or_open!(Seal, SealingKey, $crypt)
                } else {
                    seal_or_open!(Open, OpeningKey, $crypt)
                }
            };
        }

        match t {
            CipherType::Aes128Gcm => seal_or_open!(AES_128_GCM),
            CipherType::Aes256Gcm => seal_or_open!(AES_256_GCM),
            CipherType::ChaCha20Poly1305 => seal_or_open!(CHACHA20_POLY1305),
            _ => panic!("unsupported cipher in ring {:?}", t),
        }
    }

    fn increase_nonce(&mut self) {
        increase_nonce(&mut self.nonce);
    }

    fn reset(&mut self) {
        self.increase_nonce();
        let is_seal = match self.cipher {
            RingAeadCryptoVariant::Seal(..) => true,
            RingAeadCryptoVariant::Open(..) => false,
        };
        let var = RingAeadCipher::new_variant(self.cipher_type, &self.key, &self.nonce, is_seal);
        mem::replace(&mut self.cipher, var);
    }
}

impl AeadEncryptor for RingAeadCipher {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]) {
        let tag_len = tag.len();
        let buf_len = input.len() + tag_len;

        let mut buf = BytesMut::with_capacity(buf_len);
        buf.put_slice(input);
        unsafe {
            buf.set_len(buf_len);
        }

        if let RingAeadCryptoVariant::Seal(ref key, ref nonce) = self.cipher {
            seal_in_place(key, nonce, &[], &mut buf, tag_len).unwrap();
            output.copy_from_slice(&buf[..input.len()]);
            tag.copy_from_slice(&buf[input.len()..]);
        } else {
            unreachable!("encrypt is called on a non-seal cipher");
        }

        self.reset();
    }
}

impl AeadDecryptor for RingAeadCipher {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> CipherResult<()> {
        let mut buf = BytesMut::with_capacity(input.len() + tag.len());
        buf.put_slice(input);
        buf.put_slice(tag);

        let r = if let RingAeadCryptoVariant::Open(ref key, ref nonce) = self.cipher {
            match open_in_place(key, nonce, &[], 0, &mut buf) {
                Ok(buf) => {
                    output.copy_from_slice(&buf[..input.len()]);
                    Ok(())
                }
                Err(err) => {
                    error!("AEAD decrypt failed, nonce={:?}, input={:?}, tag={:?}, err: {:?}",
                           ByteStr::new(nonce),
                           ByteStr::new(input),
                           ByteStr::new(tag),
                           err);
                    Err(Error::AeadDecryptFailed)
                }
            }
        } else {
            unreachable!("decrypt is called on a non-open cipher");
        };

        self.reset();

        r
    }
}
