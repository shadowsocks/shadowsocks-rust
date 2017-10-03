//! Ciphers

use std::cell::RefCell;
use std::convert::From;
use std::fmt::{self, Debug, Display};
use std::io;
use std::mem;
use std::str::{self, FromStr};

use bytes::{BufMut, Bytes, BytesMut};
use crypto::digest::{self, Digest, DigestType};
use openssl::symm;
use rand::{OsRng, Rng};
use ring::aead::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

/// Cipher result
pub type CipherResult<T> = Result<T, Error>;

/// Cipher error
pub enum Error {
    UnknownCipherType,
    OpenSSLError(::openssl::error::ErrorStack),
    IoError(io::Error),
    AeadDecryptFailed,
    SodiumError,
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            Error::OpenSSLError(ref err) => write!(f, "{:?}", err),
            Error::IoError(ref err) => write!(f, "{:?}", err),
            Error::AeadDecryptFailed => write!(f, "AEAD decrypt failed"),
            Error::SodiumError => write!(f, "Sodium error"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownCipherType => write!(f, "UnknownCipherType"),
            Error::OpenSSLError(ref err) => write!(f, "{}", err),
            Error::IoError(ref err) => write!(f, "{}", err),
            Error::AeadDecryptFailed => write!(f, "AeadDecryptFailed"),
            Error::SodiumError => write!(f, "Sodium error"),
        }
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::UnknownCipherType => io::Error::new(io::ErrorKind::Other, "Unknown Cipher type"),
            Error::OpenSSLError(err) => From::from(err),
            Error::IoError(err) => err,
            Error::AeadDecryptFailed => io::Error::new(io::ErrorKind::Other, "AEAD decrypt error"),
            Error::SodiumError => io::Error::new(io::ErrorKind::Other, "Sodium error"),
        }
    }
}

impl From<::openssl::error::ErrorStack> for Error {
    fn from(e: ::openssl::error::ErrorStack) -> Error {
        Error::OpenSSLError(e)
    }
}

const CIPHER_AES_128_CFB: &'static str = "aes-128-cfb";
const CIPHER_AES_128_CFB_1: &'static str = "aes-128-cfb1";
const CIPHER_AES_128_CFB_8: &'static str = "aes-128-cfb8";
const CIPHER_AES_128_CFB_128: &'static str = "aes-128-cfb128";

const CIPHER_AES_256_CFB: &'static str = "aes-256-cfb";
const CIPHER_AES_256_CFB_1: &'static str = "aes-256-cfb1";
const CIPHER_AES_256_CFB_8: &'static str = "aes-256-cfb8";
const CIPHER_AES_256_CFB_128: &'static str = "aes-256-cfb128";

const CIPHER_RC4: &'static str = "rc4";
const CIPHER_RC4_MD5: &'static str = "rc4-md5";

const CIPHER_TABLE: &'static str = "table";

const CIPHER_CHACHA20: &'static str = "chacha20";
const CIPHER_SALSA20: &'static str = "salsa20";
const CIPHER_XSALSA20: &'static str = "xsalsa20";
const CIPHER_CHACHA20_IETF: &'static str = "chacha20-ietf";

const CIPHER_DUMMY: &'static str = "dummy";

const CIPHER_AES_128_GCM: &'static str = "aes-128-gcm";
const CIPHER_AES_256_GCM: &'static str = "aes-256-gcm";
const CIPHER_CHACHA20_POLY1305: &'static str = "chacha20-ietf-poly1305";

/// ShadowSocks cipher type
#[derive(Clone, Debug, Copy)]
pub enum CipherType {
    Table,
    Dummy,

    Aes128Cfb,
    Aes128Cfb1,
    Aes128Cfb8,
    Aes128Cfb128,

    Aes256Cfb,
    Aes256Cfb1,
    Aes256Cfb8,
    Aes256Cfb128,

    Rc4,
    Rc4Md5,

    ChaCha20,
    Salsa20,
    XSalsa20,
    ChaCha20Ietf,

    Aes128Gcm,
    Aes256Gcm,

    ChaCha20Poly1305,
}

/// Category of ciphers
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CipherCategory {
    /// Stream ciphers is used for OLD ShadowSocks protocol, which uses stream ciphers to encrypt data payloads
    Stream,
    /// AEAD ciphers is used in modern ShadowSocks protocol, which sends data in separate packets
    Aead,
}

impl CipherType {
    /// Symmetric crypto key size
    pub fn key_size(&self) -> usize {
        match *self {
            CipherType::Table | CipherType::Dummy => 0,

            CipherType::Aes128Cfb1 => symm::Cipher::aes_128_cfb1().key_len(),
            CipherType::Aes128Cfb8 => symm::Cipher::aes_128_cfb8().key_len(),
            CipherType::Aes128Cfb |
            CipherType::Aes128Cfb128 => symm::Cipher::aes_128_cfb128().key_len(),
            CipherType::Aes256Cfb1 => symm::Cipher::aes_256_cfb1().key_len(),
            CipherType::Aes256Cfb8 => symm::Cipher::aes_256_cfb8().key_len(),
            CipherType::Aes256Cfb |
            CipherType::Aes256Cfb128 => symm::Cipher::aes_256_cfb128().key_len(),

            CipherType::Rc4 |
            CipherType::Rc4Md5 => symm::Cipher::rc4().key_len(),

            CipherType::ChaCha20 |
            CipherType::Salsa20 |
            CipherType::XSalsa20 |
            CipherType::ChaCha20Ietf => 32,

            CipherType::Aes128Gcm => AES_128_GCM.key_len(),
            CipherType::Aes256Gcm => AES_256_GCM.key_len(),

            CipherType::ChaCha20Poly1305 => CHACHA20_POLY1305.key_len(),
        }
    }

    fn classic_bytes_to_key(&self, key: &[u8]) -> Bytes {
        let iv_len = self.iv_size();
        let key_len = self.key_size();

        if iv_len + key_len == 0 {
            return Bytes::new();
        }

        let mut digest = digest::with_type(DigestType::Md5);

        let total_loop = (key_len + iv_len + digest.digest_len() - 1) / digest.digest_len();
        let m_length = digest.digest_len() + key.len();

        let mut result = BytesMut::with_capacity(total_loop * digest.digest_len());
        let mut m = BytesMut::with_capacity(key.len());

        for _ in 0..total_loop {
            let mut vkey = mem::replace(&mut m, BytesMut::with_capacity(m_length));
            vkey.put(key);

            digest.update(&vkey);
            digest.digest(&mut m);
            digest.reset();

            result.put_slice(&m);
        }

        result.truncate(key_len);
        result.freeze()
    }

    /// Extends key to match the required key length
    pub fn bytes_to_key(&self, key: &[u8]) -> Bytes {
        self.classic_bytes_to_key(key)
    }

    /// Symmetric crypto initialize vector size
    pub fn iv_size(&self) -> usize {
        match *self {
            CipherType::Table | CipherType::Dummy => 0,

            CipherType::Aes128Cfb1 => {
                symm::Cipher::aes_128_cfb1()
                    .iv_len()
                    .expect("iv_len should not be None")
            }
            CipherType::Aes128Cfb8 => {
                symm::Cipher::aes_128_cfb8()
                    .iv_len()
                    .expect("iv_len should not be None")
            }
            CipherType::Aes128Cfb |
            CipherType::Aes128Cfb128 => {
                symm::Cipher::aes_128_cfb128()
                    .iv_len()
                    .expect("iv_len should not be None")
            }
            CipherType::Aes256Cfb1 => {
                symm::Cipher::aes_256_cfb1()
                    .iv_len()
                    .expect("iv_len should not be None")
            }
            CipherType::Aes256Cfb8 => {
                symm::Cipher::aes_256_cfb8()
                    .iv_len()
                    .expect("iv_len should not be None")
            }
            CipherType::Aes256Cfb |
            CipherType::Aes256Cfb128 => {
                symm::Cipher::aes_256_cfb128()
                    .iv_len()
                    .expect("iv_len should not be None")
            }

            CipherType::Rc4 => {
                symm::Cipher::rc4()
                    .iv_len()
                    .expect("iv_len should not be None")
            }
            CipherType::Rc4Md5 => 16,

            CipherType::ChaCha20 |
            CipherType::Salsa20 => 8,
            CipherType::XSalsa20 => 24,
            CipherType::ChaCha20Ietf => 12,

            CipherType::Aes128Gcm => AES_128_GCM.nonce_len(),
            CipherType::Aes256Gcm => AES_256_GCM.nonce_len(),
            CipherType::ChaCha20Poly1305 => CHACHA20_POLY1305.nonce_len(),
        }
    }

    fn gen_random_bytes(len: usize) -> Bytes {
        thread_local!(static RNG: RefCell<OsRng> = RefCell::new(OsRng::new().unwrap()));

        RNG.with(|rng| {
            let mut brng = rng.borrow_mut();

            let mut iv = BytesMut::with_capacity(len);
            unsafe {
                iv.set_len(len);
            }

            brng.fill_bytes(&mut iv);
            iv.freeze()
        })
    }

    /// Generate a random initialize vector for this cipher
    pub fn gen_init_vec(&self) -> Bytes {
        let iv_len = self.iv_size();
        CipherType::gen_random_bytes(iv_len)
    }

    /// Get category of cipher
    pub fn category(&self) -> CipherCategory {
        match *self {
            CipherType::Aes128Gcm |
            CipherType::Aes256Gcm |
            CipherType::ChaCha20Poly1305 => CipherCategory::Aead,
            _ => CipherCategory::Stream,
        }
    }

    /// Get tag size for AEAD Ciphers
    pub fn tag_size(&self) -> usize {
        assert!(self.category() == CipherCategory::Aead);

        match *self {
            CipherType::Aes128Gcm => AES_128_GCM.tag_len(),
            CipherType::Aes256Gcm => AES_256_GCM.tag_len(),
            CipherType::ChaCha20Poly1305 => CHACHA20_POLY1305.tag_len(),

            _ => panic!("Only support AEAD ciphers, found {:?}", self),
        }
    }

    /// Get nonce size for AEAD ciphers
    pub fn salt_size(&self) -> usize {
        assert!(self.category() == CipherCategory::Aead);
        self.key_size()
    }

    /// Get salt for AEAD ciphers
    pub fn gen_salt(&self) -> Bytes {
        CipherType::gen_random_bytes(self.salt_size())
    }
}

impl FromStr for CipherType {
    type Err = Error;
    fn from_str(s: &str) -> Result<CipherType, Error> {
        match s {
            CIPHER_TABLE | "" => Ok(CipherType::Table),
            CIPHER_DUMMY => Ok(CipherType::Dummy),
            CIPHER_AES_128_CFB => Ok(CipherType::Aes128Cfb),
            CIPHER_AES_128_CFB_1 => Ok(CipherType::Aes128Cfb1),
            CIPHER_AES_128_CFB_8 => Ok(CipherType::Aes128Cfb8),
            CIPHER_AES_128_CFB_128 => Ok(CipherType::Aes128Cfb128),

            CIPHER_AES_256_CFB => Ok(CipherType::Aes256Cfb),
            CIPHER_AES_256_CFB_1 => Ok(CipherType::Aes256Cfb1),
            CIPHER_AES_256_CFB_8 => Ok(CipherType::Aes256Cfb8),
            CIPHER_AES_256_CFB_128 => Ok(CipherType::Aes256Cfb128),

            CIPHER_RC4 => Ok(CipherType::Rc4),
            CIPHER_RC4_MD5 => Ok(CipherType::Rc4Md5),

            CIPHER_CHACHA20 => Ok(CipherType::ChaCha20),
            CIPHER_SALSA20 => Ok(CipherType::Salsa20),
            CIPHER_XSALSA20 => Ok(CipherType::XSalsa20),
            CIPHER_CHACHA20_IETF => Ok(CipherType::ChaCha20Ietf),

            CIPHER_AES_128_GCM => Ok(CipherType::Aes128Gcm),
            CIPHER_AES_256_GCM => Ok(CipherType::Aes256Gcm),

            CIPHER_CHACHA20_POLY1305 => Ok(CipherType::ChaCha20Poly1305),

            _ => Err(Error::UnknownCipherType),
        }
    }
}

impl Display for CipherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherType::Table => write!(f, "{}", CIPHER_TABLE),
            CipherType::Dummy => write!(f, "{}", CIPHER_DUMMY),
            CipherType::Aes128Cfb => write!(f, "{}", CIPHER_AES_128_CFB),
            CipherType::Aes128Cfb1 => write!(f, "{}", CIPHER_AES_128_CFB_1),
            CipherType::Aes128Cfb8 => write!(f, "{}", CIPHER_AES_128_CFB_8),
            CipherType::Aes128Cfb128 => write!(f, "{}", CIPHER_AES_128_CFB_128),

            CipherType::Aes256Cfb => write!(f, "{}", CIPHER_AES_256_CFB),
            CipherType::Aes256Cfb1 => write!(f, "{}", CIPHER_AES_256_CFB_1),
            CipherType::Aes256Cfb8 => write!(f, "{}", CIPHER_AES_256_CFB_8),
            CipherType::Aes256Cfb128 => write!(f, "{}", CIPHER_AES_256_CFB_128),

            CipherType::Rc4 => write!(f, "{}", CIPHER_RC4),
            CipherType::Rc4Md5 => write!(f, "{}", CIPHER_RC4_MD5),

            CipherType::ChaCha20 => write!(f, "{}", CIPHER_CHACHA20),
            CipherType::Salsa20 => write!(f, "{}", CIPHER_SALSA20),
            CipherType::XSalsa20 => write!(f, "{}", CIPHER_XSALSA20),
            CipherType::ChaCha20Ietf => write!(f, "{}", CIPHER_CHACHA20_IETF),

            CipherType::Aes128Gcm => write!(f, "{}", CIPHER_AES_128_GCM),
            CipherType::Aes256Gcm => write!(f, "{}", CIPHER_AES_256_GCM),
            CipherType::ChaCha20Poly1305 => write!(f, "{}", CIPHER_CHACHA20_POLY1305),
        }
    }
}

#[cfg(test)]
mod test_cipher {
    use crypto::{CipherType, StreamCipher, new_stream};
    use crypto::CryptoMode;

    #[test]
    fn test_get_cipher() {
        let key = CipherType::Aes128Cfb.bytes_to_key(b"PassWORD");
        let iv = CipherType::Aes128Cfb.gen_init_vec();
        let mut encryptor = new_stream(CipherType::Aes128Cfb, &key[0..], &iv[0..], CryptoMode::Encrypt);
        let mut decryptor = new_stream(CipherType::Aes128Cfb, &key[0..], &iv[0..], CryptoMode::Decrypt);
        let message = "HELLO WORLD";

        let mut encrypted_msg = Vec::new();
        encryptor.update(message.as_bytes(), &mut encrypted_msg)
                 .unwrap();
        let mut decrypted_msg = Vec::new();
        decryptor.update(&encrypted_msg[..], &mut decrypted_msg)
                 .unwrap();

        assert!(message.as_bytes() == &decrypted_msg[..]);
    }

    #[test]
    fn test_rc4_md5_key_iv() {
        let ty = CipherType::Rc4Md5;
        assert_eq!(ty.key_size(), 16);
        assert_eq!(ty.iv_size(), 16);
    }
}
