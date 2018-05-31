//! Cipher defined with Miscreant

use std::ptr;

use miscreant::aead::{Aes128PmacSiv, Aes256PmacSiv, Algorithm};

use crypto::aead::{increase_nonce, make_skey};
use crypto::cipher::Error;
use crypto::{AeadDecryptor, AeadEncryptor};
use crypto::{CipherResult, CipherType};

use bytes::{BufMut, BytesMut};

use byte_string::ByteStr;

/// AEAD ciphers provided by Miscreant
pub enum MiscreantCryptoVariant {
    Aes128(Aes128PmacSiv),
    Aes256(Aes256PmacSiv),
}

/// AEAD Cipher context
///
/// According to SIP004, the `nonce` has to incr 1 after each encrypt/decrypt.
pub struct MiscreantCipher {
    cipher_type: CipherType,
    cipher: MiscreantCryptoVariant,
    nonce: BytesMut,
}

impl MiscreantCipher {
    /// Initialize context
    pub fn new(t: CipherType, key: &[u8], salt: &[u8]) -> Self {
        // NOTE: Don't need check salt is duplicated. :)

        let nonce_size = t.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        unsafe {
            nonce.set_len(nonce_size);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
        }

        let skey = make_skey(t, key, salt);
        let cipher = Self::new_variant(t, &skey);
        MiscreantCipher { cipher_type: t,
                          cipher: cipher,
                          nonce: nonce, }
    }

    fn new_variant(t: CipherType, key: &[u8]) -> MiscreantCryptoVariant {
        match t {
            CipherType::Aes128PmacSiv => {
                let mut skey = [0; 32];
                skey.copy_from_slice(key);
                MiscreantCryptoVariant::Aes128(Aes128PmacSiv::new(&skey))
            }
            CipherType::Aes256PmacSiv => {
                let mut skey = [0; 64];
                skey.copy_from_slice(key);
                MiscreantCryptoVariant::Aes256(Aes256PmacSiv::new(&skey))
            }
            _ => panic!("unsupported cipher in miscreant {:?}", t),
        }
    }
}

impl AeadEncryptor for MiscreantCipher {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        let tag_len = self.cipher_type.tag_size();
        let buf_len = input.len() + tag_len;

        let mut buf = BytesMut::with_capacity(buf_len);
        unsafe {
            buf.set_len(buf_len);
        }
        buf[tag_len..].copy_from_slice(input);

        match self.cipher {
            MiscreantCryptoVariant::Aes128(ref mut cipher) => {
                cipher.seal_in_place(&self.nonce, b"", &mut buf);
                (&mut output[..input.len()]).copy_from_slice(&buf[tag_len..]);
                (&mut output[input.len()..]).copy_from_slice(&buf[..tag_len]);
            }
            MiscreantCryptoVariant::Aes256(ref mut cipher) => {
                cipher.seal_in_place(&self.nonce, b"", &mut buf);
                (&mut output[..input.len()]).copy_from_slice(&buf[tag_len..]);
                (&mut output[input.len()..]).copy_from_slice(&buf[..tag_len]);
            }
        }

        increase_nonce(&mut self.nonce);
    }
}

impl AeadDecryptor for MiscreantCipher {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> CipherResult<()> {
        let tag_size = self.cipher_type.tag_size();
        let mut buf = BytesMut::with_capacity(input.len() + tag_size);
        buf.put_slice(&input[input.len() - tag_size..]);
        buf.put_slice(&input[..input.len() - tag_size]);

        let result = match self.cipher {
            MiscreantCryptoVariant::Aes128(ref mut cipher) => cipher.open_in_place(&self.nonce, b"", &mut buf),
            MiscreantCryptoVariant::Aes256(ref mut cipher) => cipher.open_in_place(&self.nonce, b"", &mut buf),
        };

        result.map(|buf| {
                       output.copy_from_slice(buf);
                       increase_nonce(&mut self.nonce);
                   })
              .map_err(|_| {
                           error!("AEAD decrypt failed, nonce={:?}, input={:?}, tag={:?}, err: decrypt failure",
                                  ByteStr::new(&self.nonce),
                                  ByteStr::new(&input[..input.len() - tag_size]),
                                  ByteStr::new(&input[input.len() - tag_size..]));
                           Error::AeadDecryptFailed
                       })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto::{AeadDecryptor, AeadEncryptor, CipherType};

    fn test_miscreant(ct: CipherType) {
        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = MiscreantCipher::new(ct, &key[..], &iv[..]);

        let mut encrypted_msg = vec![0u8; message.len() + ct.tag_size()];
        enc.encrypt(message, &mut encrypted_msg);

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = MiscreantCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = vec![0u8; message.len()];
        dec.decrypt(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    #[test]
    fn test_rust_crypto_cipher_aes_128_pmac_siv() {
        test_miscreant(CipherType::Aes128PmacSiv);
    }

    #[test]
    fn test_rust_crypto_cipher_aes_256_pmac_siv() {
        test_miscreant(CipherType::Aes256PmacSiv);
    }
}
