//! Cipher defined with libsodium

use bytes::{BufMut, BytesMut};

use crypto::{CipherResult, CipherType, StreamCipher};

use libc::c_ulonglong;
use libsodium_ffi::{crypto_stream_aes128ctr_xor, crypto_stream_chacha20_ietf_xor_ic, crypto_stream_chacha20_xor_ic,
                    crypto_stream_salsa20_xor_ic, crypto_stream_xsalsa20_xor_ic};

use crypto::cipher::Error;

/// Cipher provided by Rust-Crypto
pub struct SodiumCipher {
    cipher_type: CipherType,
    key: Vec<u8>,
    iv: Vec<u8>,
    counter: usize,
}

const SODIUM_BLOCK_SIZE: usize = 64;

impl SodiumCipher {
    /// Creates an instance
    pub fn new(t: CipherType, key: &[u8], iv: &[u8]) -> SodiumCipher {
        match t {
            CipherType::ChaCha20 |
            CipherType::Salsa20 |
            CipherType::XSalsa20 |
            CipherType::Aes128Ctr |
            CipherType::ChaCha20Ietf => {}
            _ => panic!("sodium cipher does not support {:?} cipher", t),
        }

        SodiumCipher {
            cipher_type: t,
            key: key.to_owned(),
            iv: iv.to_owned(),
            counter: 0,
        }
    }

    fn padding_len(&self) -> usize {
        self.counter % SODIUM_BLOCK_SIZE
    }

    fn process<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        let padding = self.padding_len();

        let mut plain_text = vec![0u8; data.len() + padding];
        (&mut plain_text[padding..]).copy_from_slice(&data);

        let mut out_buf = BytesMut::with_capacity((data.len() + padding) * 2);

        crypto_stream_xor_ic(self.cipher_type,
                             self.counter / SODIUM_BLOCK_SIZE,
                             &self.iv,
                             &self.key,
                             &plain_text,
                             &mut out_buf)?;

        out.put_slice(&out_buf[padding..padding + data.len()]);

        self.counter += data.len();
        Ok(())
    }
}

fn crypto_stream_xor_ic<B: BufMut>(t: CipherType,
                                   ic: usize,
                                   iv: &[u8],
                                   key: &[u8],
                                   data: &[u8],
                                   out: &mut B)
                                   -> CipherResult<()> {
    assert!(data.len() <= unsafe { out.bytes_mut().len() });

    let ret = unsafe {
        match t {
            CipherType::ChaCha20 => {
                crypto_stream_chacha20_xor_ic(out.bytes_mut().as_mut_ptr(),
                                              data.as_ptr(),
                                              data.len() as c_ulonglong,
                                              iv.as_ptr(),
                                              ic as c_ulonglong,
                                              key.as_ptr())
            }
            CipherType::ChaCha20Ietf => {
                crypto_stream_chacha20_ietf_xor_ic(out.bytes_mut().as_mut_ptr(),
                                                   data.as_ptr(),
                                                   data.len() as c_ulonglong,
                                                   iv.as_ptr(),
                                                   ic as u32,
                                                   key.as_ptr())
            }
            CipherType::Salsa20 => {
                crypto_stream_salsa20_xor_ic(out.bytes_mut().as_mut_ptr(),
                                             data.as_ptr(),
                                             data.len() as c_ulonglong,
                                             iv.as_ptr(),
                                             ic as c_ulonglong,
                                             key.as_ptr())
            }
            CipherType::XSalsa20 => {
                crypto_stream_xsalsa20_xor_ic(out.bytes_mut().as_mut_ptr(),
                                              data.as_ptr(),
                                              data.len() as c_ulonglong,
                                              iv.as_ptr(),
                                              ic as c_ulonglong,
                                              key.as_ptr())
            }
            CipherType::Aes128Ctr => {
                crypto_stream_aes128ctr_xor(out.bytes_mut().as_mut_ptr(),
                                            data.as_ptr(),
                                            data.len() as c_ulonglong,
                                            iv.as_ptr(),
                                            key.as_ptr())
            }
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

impl StreamCipher for SodiumCipher {
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



#[cfg(test)]
mod test {
    use super::*;
    use crypto::{CipherType, StreamCipher};

    fn test_sodium(ct: CipherType) {
        let key = ct.bytes_to_key(b"PassWORD");
        let message = b"message";

        let iv = ct.gen_init_vec();

        let mut enc = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut encrypted_msg = Vec::with_capacity(enc.buffer_size(&message[..]));
        enc.update(message, &mut encrypted_msg).unwrap();

        assert_ne!(message, &encrypted_msg[..]);

        let mut dec = SodiumCipher::new(ct, &key[..], &iv[..]);
        let mut decrypted_msg = Vec::with_capacity(dec.buffer_size(&encrypted_msg));
        dec.update(&encrypted_msg[..], &mut decrypted_msg).unwrap();

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
    fn test_rust_crypto_cipher_aes128ctr() {
        test_sodium(CipherType::Aes128Ctr);
    }

    #[test]
    fn test_rust_crypto_cipher_chacha20_ietf() {
        test_sodium(CipherType::ChaCha20Ietf);
    }
}
