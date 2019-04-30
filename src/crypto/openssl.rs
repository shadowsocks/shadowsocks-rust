//! Cipher defined with Rust binding for libcrypto (OpenSSL)

use std::convert::From;

use crate::crypto::{cipher, CipherResult, CipherType, StreamCipher};

use crate::crypto::CryptoMode;

use bytes::{BufMut, BytesMut};
use openssl::symm;

/// Core cipher of OpenSSL
pub struct OpenSSLCrypto {
    cipher: symm::Cipher,
    inner: symm::Crypter,
}

impl OpenSSLCrypto {
    /// Creates by type
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let t = match cipher_type {
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb => symm::Cipher::aes_128_cfb128(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes128Cfb128 => symm::Cipher::aes_128_cfb128(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb => symm::Cipher::aes_256_cfb128(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1(),
            #[cfg(feature = "aes-cfb")]
            CipherType::Aes256Cfb128 => symm::Cipher::aes_256_cfb128(),

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
    pub fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        let least_reserved = data.len() + self.cipher.block_size();
        let mut buf = BytesMut::with_capacity(least_reserved); // NOTE: len() is 0 now!
        unsafe {
            buf.set_len(least_reserved);
        }
        let length = self.inner.update(data, &mut *buf)?;
        buf.truncate(length);
        out.put(buf);
        Ok(())
    }

    /// Generate the final block
    pub fn finalize<B: BufMut>(&mut self, out: &mut B) -> CipherResult<()> {
        let least_reserved = self.cipher.block_size();
        let mut buf = BytesMut::with_capacity(least_reserved); // NOTE: len() is 0 now!
        unsafe {
            buf.set_len(least_reserved);
        }

        let length = self.inner.finalize(&mut *buf)?;
        buf.truncate(length);
        out.put(buf);
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
    fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
        self.worker.update(data, out)
    }

    fn finalize<B: BufMut>(&mut self, out: &mut B) -> CipherResult<()> {
        self.worker.finalize(out)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        self.worker.buffer_size(data)
    }
}
