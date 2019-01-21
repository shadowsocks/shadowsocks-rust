//! Cipher defined with Ring

use std::{mem, ptr};

use ring::aead::{open_in_place, seal_in_place, OpeningKey, SealingKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

use crate::crypto::{
    aead::{increase_nonce, make_skey},
    cipher::Error,
    AeadDecryptor,
    AeadEncryptor,
    CipherResult,
    CipherType,
};

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
        RingAeadCipher {
            cipher: cipher,
            cipher_type: t,
            key: skey,
            nonce: nonce,
        }
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
            CipherType::ChaCha20IetfPoly1305 => seal_or_open!(CHACHA20_POLY1305),
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
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        let tag_len = self.cipher_type.tag_size();
        let buf_len = input.len() + tag_len;
        assert_eq!(output.len(), buf_len);

        let mut buf = BytesMut::with_capacity(output.len());
        buf.put_slice(input);
        unsafe {
            buf.set_len(output.len());
        }

        if let RingAeadCryptoVariant::Seal(ref key, ref nonce) = self.cipher {
            seal_in_place(key, nonce, &[], &mut buf, tag_len).unwrap();
        } else {
            unreachable!("encrypt is called on a non-seal cipher");
        }

        output.copy_from_slice(&buf);

        self.reset();
    }
}

impl AeadDecryptor for RingAeadCipher {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> CipherResult<()> {
        let tag_len = self.cipher_type.tag_size();
        assert_eq!(output.len() + tag_len, input.len());

        let mut buf = BytesMut::with_capacity(input.len());
        buf.put_slice(input);

        let r = if let RingAeadCryptoVariant::Open(ref key, ref nonce) = self.cipher {
            match open_in_place(key, nonce, &[], 0, &mut buf) {
                Ok(obuf) => {
                    output.copy_from_slice(obuf);
                    Ok(())
                }
                Err(err) => {
                    error!(
                        "AEAD decrypt failed, nonce={:?}, input={:?}, tag={:?}, err: {:?}",
                        ByteStr::new(nonce),
                        ByteStr::new(&input[..tag_len]),
                        ByteStr::new(&input[tag_len..]),
                        err
                    );
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::CipherType;

    fn test_ring_aead(ct: CipherType) {
        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = RingAeadCipher::new(ct, &key[..], &iv[..], true);

        let mut encrypted_msg = vec![0u8; message.len() + ct.tag_size()];
        enc.encrypt(message, &mut encrypted_msg);

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = RingAeadCipher::new(ct, &key[..], &iv[..], false);
        let mut decrypted_msg = vec![0u8; message.len()];
        dec.decrypt(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    #[test]
    fn test_ring_aes128gcm() {
        test_ring_aead(CipherType::Aes128Gcm);
    }

    #[test]
    fn test_ring_aes256gcm() {
        test_ring_aead(CipherType::Aes256Gcm);
    }

    #[test]
    fn test_ring_chacha20poly1305() {
        test_ring_aead(CipherType::ChaCha20IetfPoly1305);
    }
}
