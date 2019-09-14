//! Cipher defined with libsodium

use std::{
    ptr,
    sync::{Once, ONCE_INIT},
};

use bytes::{BufMut, Bytes, BytesMut};

use libc::c_ulonglong;
use libsodium_ffi::{
    crypto_aead_xchacha20poly1305_ietf_decrypt, crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_stream_chacha20_ietf_xor_ic, crypto_stream_chacha20_xor_ic, crypto_stream_salsa20_xor_ic,
    crypto_stream_xsalsa20_xor_ic, sodium_init,
};

use crate::crypto::{
    aead::{increase_nonce, make_skey},
    cipher::Error,
    AeadDecryptor, AeadEncryptor, CipherResult, CipherType, StreamCipher,
};

static SODIUM_INIT_FLAG: Once = ONCE_INIT;

/// Cipher provided by `libsodium`
pub struct SodiumStreamCipher {
    cipher_type: CipherType,
    key: Vec<u8>,
    iv: Vec<u8>,
    counter: usize,
}

const SODIUM_BLOCK_SIZE: usize = 64;

impl SodiumStreamCipher {
    /// Creates an instance
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> SodiumStreamCipher {
        match t {
            CipherType::ChaCha20 | CipherType::Salsa20 | CipherType::XSalsa20 | CipherType::ChaCha20Ietf => {}
            _ => panic!("sodium cipher does not support {:?} cipher", t),
        }

        SODIUM_INIT_FLAG.call_once(|| unsafe {
            assert_eq!(sodium_init(), 0);
        });

        SodiumStreamCipher {
            cipher_type: t,
            key: key.to_owned(),
            iv: iv.to_owned(),
            counter: 0,
        }
    }

    fn padding_len(&self) -> usize {
        self.counter % SODIUM_BLOCK_SIZE
    }

    fn process(&mut self, data: &[u8], out: &mut dyn BufMut) -> CipherResult<()> {
        let padding = self.padding_len();

        let mut plain_text = vec![0u8; data.len() + padding];
        (&mut plain_text[padding..]).copy_from_slice(&data);

        let mut out_buf = BytesMut::with_capacity((data.len() + padding) * 2);

        crypto_stream_xor_ic(
            self.cipher_type,
            self.counter / SODIUM_BLOCK_SIZE,
            &self.iv,
            &self.key,
            &plain_text,
            &mut out_buf,
        )?;

        out.put_slice(&out_buf[padding..padding + data.len()]);

        self.counter += data.len();
        Ok(())
    }
}

fn crypto_stream_xor_ic<B: BufMut>(
    t: CipherType,
    ic: usize,
    iv: &[u8],
    key: &[u8],
    data: &[u8],
    out: &mut B,
) -> CipherResult<()> {
    assert!(data.len() <= unsafe { out.bytes_mut().len() });

    let ret = unsafe {
        match t {
            CipherType::ChaCha20 => crypto_stream_chacha20_xor_ic(
                out.bytes_mut().as_mut_ptr(),
                data.as_ptr(),
                data.len() as c_ulonglong,
                iv.as_ptr(),
                ic as c_ulonglong,
                key.as_ptr(),
            ),
            CipherType::ChaCha20Ietf => crypto_stream_chacha20_ietf_xor_ic(
                out.bytes_mut().as_mut_ptr(),
                data.as_ptr(),
                data.len() as c_ulonglong,
                iv.as_ptr(),
                ic as u32,
                key.as_ptr(),
            ),
            CipherType::Salsa20 => crypto_stream_salsa20_xor_ic(
                out.bytes_mut().as_mut_ptr(),
                data.as_ptr(),
                data.len() as c_ulonglong,
                iv.as_ptr(),
                ic as c_ulonglong,
                key.as_ptr(),
            ),
            CipherType::XSalsa20 => crypto_stream_xsalsa20_xor_ic(
                out.bytes_mut().as_mut_ptr(),
                data.as_ptr(),
                data.len() as c_ulonglong,
                iv.as_ptr(),
                ic as c_ulonglong,
                key.as_ptr(),
            ),
            _ => unreachable!(),
        }
    };

    if ret != 0 {
        Err(Error::SodiumError)
    } else {
        unsafe {
            out.advance_mut(data.len());
        }

        Ok(())
    }
}

impl StreamCipher for SodiumStreamCipher {
    fn update(&mut self, data: &[u8], out: &mut dyn BufMut) -> CipherResult<()> {
        self.process(data, out)
    }

    fn finalize(&mut self, _: &mut dyn BufMut) -> CipherResult<()> {
        Ok(())
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        data.len()
    }
}

/// Cipher provided by `libsodium`
pub struct SodiumAeadCipher {
    cipher_type: CipherType,
    key: Bytes,
    nonce: BytesMut,
}

impl SodiumAeadCipher {
    pub fn new(t: CipherType, key: &[u8], salt: &[u8]) -> SodiumAeadCipher {
        // TODO: Check if salt is duplicated

        let nonce_size = t.iv_size();
        let mut nonce = BytesMut::with_capacity(nonce_size);
        unsafe {
            nonce.set_len(nonce_size);
            ptr::write_bytes(nonce.as_mut_ptr(), 0, nonce_size);
        }

        let skey = make_skey(t, key, salt);

        SodiumAeadCipher {
            cipher_type: t,
            key: skey,
            nonce,
        }
    }

    fn increase_nonce(&mut self) {
        increase_nonce(&mut self.nonce);
    }

    fn reset(&mut self) {
        self.increase_nonce();
    }
}

impl AeadEncryptor for SodiumAeadCipher {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        let tag_len = self.cipher_type.tag_size();
        let buf_len = input.len() + tag_len;
        assert!(output.len() >= buf_len);

        let mut len: c_ulonglong = output.len() as c_ulonglong;

        let ret = match self.cipher_type {
            CipherType::XChaCha20IetfPoly1305 => unsafe {
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    output.as_mut_ptr(),
                    &mut len,
                    input.as_ptr(),
                    input.len() as c_ulonglong,
                    ptr::null(),
                    0,
                    ptr::null(),
                    self.nonce.as_ref().as_ptr(),
                    self.key.as_ref().as_ptr(),
                )
            },
            _ => unreachable!(),
        };

        self.reset();

        assert_eq!(ret, 0);
        assert_eq!(len, output.len() as c_ulonglong);
    }
}

impl AeadDecryptor for SodiumAeadCipher {
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> CipherResult<()> {
        let tag_len = self.cipher_type.tag_size();
        assert!(output.len() >= input.len() - tag_len);

        let mut len: c_ulonglong = output.len() as c_ulonglong;

        let ret = match self.cipher_type {
            CipherType::XChaCha20IetfPoly1305 => unsafe {
                crypto_aead_xchacha20poly1305_ietf_decrypt(
                    output.as_mut_ptr(),
                    &mut len,
                    ptr::null_mut(),
                    input.as_ptr(),
                    input.len() as c_ulonglong,
                    ptr::null(),
                    0,
                    self.nonce.as_ref().as_ptr(),
                    self.key.as_ref().as_ptr(),
                )
            },
            _ => unreachable!(),
        };

        self.reset();

        if ret != 0 || len != output.len() as c_ulonglong {
            return Err(Error::SodiumError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{CipherType, StreamCipher};

    fn test_sodium(ct: CipherType) {
        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = SodiumStreamCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::with_capacity(enc.buffer_size(&message[..]));
        enc.update(message, &mut encrypted_msg).unwrap();

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = SodiumStreamCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::with_capacity(dec.buffer_size(&encrypted_msg));
        dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    fn test_sodium_aead(ct: CipherType) {
        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = SodiumAeadCipher::new(ct, &key[..], &iv[..]);

        let mut encrypted_msg = vec![0u8; message.len() + ct.tag_size()];
        enc.encrypt(message, &mut encrypted_msg);

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = SodiumAeadCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = vec![0u8; message.len()];
        dec.decrypt(&encrypted_msg[..], &mut decrypted_msg).unwrap();

        assert_eq!(&decrypted_msg[..], message);
    }

    #[test]
    fn test_rust_crypto_cipher_chacha20() {
        test_sodium(CipherType::ChaCha20);
    }

    #[test]
    fn test_rust_crypto_cipher_salsa20() {
        test_sodium(CipherType::Salsa20);
    }

    #[test]
    fn test_rust_crypto_cipher_xsalsa20() {
        test_sodium(CipherType::XSalsa20);
    }

    #[test]
    fn test_rust_crypto_cipher_chacha20_ietf() {
        test_sodium(CipherType::ChaCha20Ietf);
    }

    #[test]
    fn test_rust_crypto_cipher_xchacha20_ietf_poly1305() {
        test_sodium_aead(CipherType::XChaCha20IetfPoly1305);
    }
}
