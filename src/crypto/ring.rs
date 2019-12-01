//! Cipher defined with Ring

use ring::{
    aead::{
        Aad, Algorithm, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_128_GCM, AES_256_GCM,
        CHACHA20_POLY1305, NONCE_LEN,
    },
    error::Unspecified,
};

use crate::crypto::{
    aead::{increase_nonce, make_skey},
    cipher::Error,
    AeadDecryptor, AeadEncryptor, CipherResult, CipherType,
};

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use log::error;

/// AEAD ciphers provided by Ring
pub enum RingAeadCryptoVariant {
    Seal(SealingKey<RingAeadNonceSequence>),
    Open(OpeningKey<RingAeadNonceSequence>),
}

pub struct RingAeadNonceSequence {
    nonce: [u8; NONCE_LEN],
}

impl RingAeadNonceSequence {
    fn new() -> RingAeadNonceSequence {
        RingAeadNonceSequence {
            nonce: [0u8; NONCE_LEN],
        }
    }
}

impl NonceSequence for RingAeadNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        increase_nonce(&mut self.nonce);
        Ok(nonce)
    }
}

/// AEAD Cipher context
///
/// According to SIP004, the `nonce` has to incr 1 after each encrypt/decrypt.
pub struct RingAeadCipher {
    cipher: RingAeadCryptoVariant,
    cipher_type: CipherType,
}

impl RingAeadCipher {
    /// Initialize context
    pub fn new(t: CipherType, key: &[u8], salt: &[u8], is_seal: bool) -> RingAeadCipher {
        // TODO: Check if salt is duplicated

        // Nonce is 12 bytes
        assert_eq!(t.iv_size(), NONCE_LEN);

        let skey = make_skey(t, key, salt);
        let cipher = RingAeadCipher::new_variant(t, &skey, is_seal);
        RingAeadCipher { cipher, cipher_type: t }
    }

    fn new_variant(t: CipherType, key: &[u8], is_seal: bool) -> RingAeadCryptoVariant {
        match t {
            CipherType::Aes128Gcm => RingAeadCipher::new_crypt(&AES_128_GCM, key, is_seal),
            CipherType::Aes256Gcm => RingAeadCipher::new_crypt(&AES_256_GCM, key, is_seal),
            CipherType::ChaCha20IetfPoly1305 => RingAeadCipher::new_crypt(&CHACHA20_POLY1305, key, is_seal),
            _ => panic!("unsupported cipher in ring {:?}", t),
        }
    }

    #[inline]
    fn new_crypt(algorithm: &'static Algorithm, key: &[u8], is_seal: bool) -> RingAeadCryptoVariant {
        use ring::aead::BoundKey;

        let unbound_key = UnboundKey::new(algorithm, key).unwrap();

        if is_seal {
            RingAeadCryptoVariant::Seal(SealingKey::new(unbound_key, RingAeadNonceSequence::new()))
        } else {
            RingAeadCryptoVariant::Open(OpeningKey::new(unbound_key, RingAeadNonceSequence::new()))
        }
    }
}

impl AeadEncryptor for RingAeadCipher {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        let tag_len = self.cipher_type.tag_size();
        let buf_len = input.len() + tag_len;
        assert_eq!(output.len(), buf_len);

        let mut buf = BytesMut::with_capacity(output.len());
        buf.put_slice(input);

        if let RingAeadCryptoVariant::Seal(ref mut key) = self.cipher {
            key.seal_in_place_append_tag(Aad::empty(), &mut buf).unwrap();
        } else {
            unreachable!("encrypt is called on a non-seal cipher");
        }

        output.copy_from_slice(&buf[..buf_len]);
    }
}

impl AeadDecryptor for RingAeadCipher {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> CipherResult<()> {
        let tag_len = self.cipher_type.tag_size();
        assert_eq!(output.len() + tag_len, input.len());

        let mut buf = BytesMut::with_capacity(input.len());
        buf.put_slice(input);

        if let RingAeadCryptoVariant::Open(ref mut key) = self.cipher {
            match key.open_in_place(Aad::empty(), &mut buf) {
                Ok(obuf) => {
                    output.copy_from_slice(obuf);
                    Ok(())
                }
                Err(..) => {
                    error!(
                        "AEAD decrypt failed, input={:?}, tag={:?}, opening: {:?}",
                        ByteStr::new(&input[..output.len()]),
                        ByteStr::new(&input[output.len()..]),
                        key,
                    );
                    Err(Error::AeadDecryptFailed)
                }
            }
        } else {
            unreachable!("decrypt is called on a non-open cipher");
        }
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
