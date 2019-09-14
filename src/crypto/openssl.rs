//! Cipher defined with Rust binding for libcrypto (OpenSSL)

use std::convert::From;

use crate::crypto::{cipher, CipherResult, CipherType, StreamCipher};

use crate::crypto::CryptoMode;

use bytes::{BufMut, BytesMut};
#[cfg(feature = "camellia-cfb")]
use openssl::nid::Nid;
use openssl::symm;

/// Core cipher of OpenSSL
pub struct OpenSSLCrypto {
    cipher: symm::Cipher,
    inner: symm::Crypter,
}

impl OpenSSLCrypto {
    /// Creates by type
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let t =
            match cipher_type {
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes128Cfb => symm::Cipher::aes_128_cfb128(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes128Cfb128 => symm::Cipher::aes_128_cfb128(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes192Cfb => symm::Cipher::aes_192_cfb128(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes192Cfb1 => symm::Cipher::aes_192_cfb1(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes192Cfb128 => symm::Cipher::aes_192_cfb128(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes256Cfb => symm::Cipher::aes_256_cfb128(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1(),
                #[cfg(feature = "aes-cfb")]
                CipherType::Aes256Cfb128 => symm::Cipher::aes_256_cfb128(),

                #[cfg(feature = "aes-ctr")]
                CipherType::Aes128Ctr => symm::Cipher::aes_128_ctr(),
                #[cfg(feature = "aes-ctr")]
                CipherType::Aes192Ctr => symm::Cipher::aes_192_ctr(),
                #[cfg(feature = "aes-ctr")]
                CipherType::Aes256Ctr => symm::Cipher::aes_256_ctr(),

                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia128Cfb => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB128).expect("openssl doesn't support camellia-128-cfb")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia128Cfb1 => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB1).expect("openssl doesn't support camellia-128-cfb1")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia128Cfb8 => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB8).expect("openssl doesn't support camellia-128-cfb8")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia128Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_128_CFB128)
                    .expect("openssl doesn't support camellia-128-cfb128"),
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia192Cfb => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB128).expect("openssl doesn't support camellia-192-cfb")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia192Cfb1 => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB1).expect("openssl doesn't support camellia-192-cfb1")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia192Cfb8 => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB8).expect("openssl doesn't support camellia-192-cfb8")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia192Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_192_CFB128)
                    .expect("openssl doesn't support camellia-192-cfb128"),
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia256Cfb => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB128).expect("openssl doesn't support camellia-256-cfb")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia256Cfb1 => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB1).expect("openssl doesn't support camellia-256-cfb1")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia256Cfb8 => {
                    symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB8).expect("openssl doesn't support camellia-256-cfb8")
                }
                #[cfg(feature = "camellia-cfb")]
                CipherType::Camellia256Cfb128 => symm::Cipher::from_nid(Nid::CAMELLIA_256_CFB128)
                    .expect("openssl doesn't support camellia-256-cfb128"),

                #[cfg(feature = "rc4")]
                CipherType::Rc4 => symm::Cipher::rc4(),
                _ => panic!("Cipher type {:?} does not supported by OpenSSLCrypt yet", cipher_type),
            };

        // Panic if error occurs
        let cipher = symm::Crypter::new(t, From::from(mode), key, Some(iv)).unwrap();

        OpenSSLCrypto {
            cipher: t,
            inner: cipher,
        }
    }

    /// Update data
    pub fn update(&mut self, data: &[u8], out: &mut dyn BufMut) -> CipherResult<()> {
        let least_reserved = data.len() + self.cipher.block_size();
        let mut buf = BytesMut::with_capacity(least_reserved); // NOTE: len() is 0 now!
        unsafe {
            buf.set_len(least_reserved);
        }
        let length = self.inner.update(data, &mut *buf)?;
        buf.truncate(length);
        out.put_slice(&buf);
        Ok(())
    }

    /// Generate the final block
    pub fn finalize(&mut self, out: &mut dyn BufMut) -> CipherResult<()> {
        let least_reserved = self.cipher.block_size();
        let mut buf = BytesMut::with_capacity(least_reserved); // NOTE: len() is 0 now!
        unsafe {
            buf.set_len(least_reserved);
        }

        let length = self.inner.finalize(&mut *buf)?;
        buf.truncate(length);
        out.put_slice(&buf);
        Ok(())
    }

    /// Gets output buffer size based on data
    pub fn buffer_size(&self, data: &[u8]) -> usize {
        self.cipher.block_size() + data.len()
    }
}

/// The Cipher binding for OpenSSL's `libcrypto`.
///
/// It should be noticed that the decipher needs to read the iv (initialization vector)
/// from the first call of `decrypt`. So the cipher will have to insert the iv into
/// the front of the encrypted data.
///
/// *Note: This behavior works just the same as the official version of shadowsocks.*
///
/// ```rust
/// use shadowsocks::crypto::{openssl::OpenSSLCipher, CipherType, CryptoMode, StreamCipher};
///
/// let method = CipherType::Aes128Cfb;
///
/// let key = method.bytes_to_key(b"password");
/// let iv = method.gen_init_vec();
///
/// let mut enc = OpenSSLCipher::new(method, &key[0..], &iv[0..], CryptoMode::Encrypt);
/// let mut dec = OpenSSLCipher::new(method, &key[0..], &iv[0..], CryptoMode::Decrypt);
///
/// let message = "hello world";
/// let mut encrypted_message = Vec::new();
/// enc.update(message.as_bytes(), &mut encrypted_message).unwrap();
///
/// let mut decrypted_message = Vec::new();
/// dec.update(&encrypted_message[..], &mut decrypted_message).unwrap();
///
/// assert!(&decrypted_message[..] == message.as_bytes());
/// ```
pub struct OpenSSLCipher {
    worker: OpenSSLCrypto,
}

impl OpenSSLCipher {
    /// Creates by type
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCipher {
        OpenSSLCipher {
            worker: OpenSSLCrypto::new(cipher_type, &key[..], &iv[..], mode),
        }
    }
}

unsafe impl Send for OpenSSLCipher {}

impl StreamCipher for OpenSSLCipher {
    fn update(&mut self, data: &[u8], out: &mut dyn BufMut) -> CipherResult<()> {
        self.worker.update(data, out)
    }

    fn finalize(&mut self, out: &mut dyn BufMut) -> CipherResult<()> {
        self.worker.finalize(out)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.worker.buffer_size(data)
    }
}
