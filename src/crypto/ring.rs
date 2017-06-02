//! Cipher defined with Ring

use std::mem;

use ring::aead::{
    AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
    SealingKey, OpeningKey,
    seal_in_place, open_in_place
};

use crypto::{CipherType, CipherResult};
use crypto::{AeadDecryptor, AeadEncryptor};
use crypto::cipher::Error;
use crypto::aead::{make_skey, increase_nonce};

use bytes::{BytesMut, BufMut, Bytes};


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
        for _ in 0..nonce_size {
            nonce.put_u8(0);
        }

        let skey = make_skey(t, key, salt);
        let cipher = RingAeadCipher::new_variant(t, &skey, &nonce, is_seal);
        RingAeadCipher {
            cipher: cipher,
            cipher_type: t,
            key: skey,
            nonce: nonce,
        }
    }

    fn new_variant(t: CipherType, key: &[u8], nonce: &[u8], is_seal: bool) -> RingAeadCryptoVariant {
        macro_rules! seal_or_open {
            ( $item:ident, $key:ident, $crypt:ident ) => {
                RingAeadCryptoVariant::$item($key::new(&$crypt, key).unwrap(), Bytes::from(nonce))
            }
        }

        match t {
            CipherType::Aes128Gcm => if is_seal {
                seal_or_open!(Seal, SealingKey, AES_128_GCM)
            } else {
                seal_or_open!(Open, OpeningKey, AES_128_GCM)
            },
            CipherType::Aes256Gcm => if is_seal {
                seal_or_open!(Seal, SealingKey, AES_256_GCM)
            } else {
                seal_or_open!(Open, OpeningKey, AES_256_GCM)
            },
            CipherType::ChaCha20Poly1305 => if is_seal {
                seal_or_open!(Seal, SealingKey, CHACHA20_POLY1305)
            } else {
                seal_or_open!(Open, OpeningKey, CHACHA20_POLY1305)
            },

            _ => panic!("Unsupported {:?}", t),
        }
    }

    fn increase_nonce(&mut self) {
        increase_nonce(&mut self.nonce);
    }

    fn reset(&mut self) {
        self.increase_nonce();
        let is_seal = match self.cipher {
            RingAeadCryptoVariant::Seal(..) => true,
            RingAeadCryptoVariant::Open(..) => false
        };
        let var = RingAeadCipher::new_variant(self.cipher_type, &self.key, &self.nonce, is_seal);
        mem::replace(&mut self.cipher, var);
    }
}

impl AeadEncryptor for RingAeadCipher {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8], tag: &mut [u8]) {
        let tag_len = tag.len();

        let mut buf = BytesMut::with_capacity(input.len() + tag_len);
        buf.put(input);
        buf.put_slice(tag);

        if let RingAeadCryptoVariant::Seal(ref key, ref nonce) = self.cipher {
            seal_in_place(key, nonce, &[], &mut buf, tag_len).unwrap();
            let (ct, t) = buf.split_at(buf.len() - tag_len);
            output.clone_from_slice(ct);
            tag.clone_from_slice(t);
        } else {
            panic!();
        }

        self.reset();
    }
}

impl AeadDecryptor for RingAeadCipher {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8], tag: &[u8]) -> CipherResult<()> {
        let mut buf = BytesMut::with_capacity(input.len() + tag.len());
        buf.put(input);
        buf.put(tag);

        let r = if let RingAeadCryptoVariant::Open(ref key, ref nonce) = self.cipher {
            match open_in_place(key, nonce, &[], 0, &mut buf) {
                Ok(buf) => {
                    output.clone_from_slice(&buf[..input.len()]);
                    Ok(())
                },
                Err(_) => Err(Error::AeadDecryptFailed)
            }
        } else {
            panic!()
        };

        self.reset();

        r
    }
}
