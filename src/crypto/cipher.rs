
use crypto::openssl;

pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub const CIPHER_AES_128_CFB: &'static str = "aes-128-cfb";
pub const CIPHER_AES_128_CFB_1: &'static str = "aes-128-cfb1";
pub const CIPHER_AES_128_CFB_8: &'static str = "aes-128-cfb8";
pub const CIPHER_AES_128_CFB_128: &'static str = "aes-128-cfb128";

pub const CIPHER_AES_192_CFB: &'static str = "aes-192-cfb";
pub const CIPHER_AES_192_CFB_1: &'static str = "aes-192-cfb1";
pub const CIPHER_AES_192_CFB_8: &'static str = "aes-192-cfb8";
pub const CIPHER_AES_192_CFB_128: &'static str = "aes-192-cfb128";

pub const CIPHER_AES_256_CFB: &'static str = "aes-256-cfb";
pub const CIPHER_AES_256_CFB_1: &'static str = "aes-256-cfb1";
pub const CIPHER_AES_256_CFB_8: &'static str = "aes-256-cfb8";
pub const CIPHER_AES_256_CFB_128: &'static str = "aes-256-cfb128";

pub enum CipherType {
    CipherTypeAes128Cfb,
    CipherTypeAes128Cfb1,
    CipherTypeAes128Cfb8,
    CipherTypeAes128Cfb128,
    CipherTypeAes192Cfb,
    CipherTypeAes192Cfb1,
    CipherTypeAes192Cfb8,
    CipherTypeAes192Cfb128,
    CipherTypeAes256Cfb,
    CipherTypeAes256Cfb1,
    CipherTypeAes256Cfb8,
    CipherTypeAes256Cfb128,
}

pub enum CipherVariant {
    OpenSSLCrypto(openssl::OpenSSLCipher),
}

impl Cipher for CipherVariant {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        match *self {
            OpenSSLCrypto(ref c) => c.encrypt(data),
        }
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        match *self {
            OpenSSLCrypto(ref c) => c.decrypt(data),
        }
    }
}

pub fn with_name(method: &str, key: &[u8]) -> Option<CipherVariant> {
    match method {
        CIPHER_AES_128_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes128Cfb, key))),
        CIPHER_AES_128_CFB_1 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes128Cfb1, key))),
        CIPHER_AES_128_CFB_8 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes128Cfb8, key))),
        CIPHER_AES_128_CFB_128 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes128Cfb128, key))),

        CIPHER_AES_192_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes192Cfb, key))),
        CIPHER_AES_192_CFB_1 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes192Cfb1, key))),
        CIPHER_AES_192_CFB_8 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes192Cfb8, key))),
        CIPHER_AES_192_CFB_128 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes192Cfb128, key))),

        CIPHER_AES_256_CFB => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes256Cfb, key))),
        CIPHER_AES_256_CFB_1 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes256Cfb1, key))),
        CIPHER_AES_256_CFB_8 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes256Cfb8, key))),
        CIPHER_AES_256_CFB_128 => Some(OpenSSLCrypto(openssl::OpenSSLCipher::new(CipherTypeAes256Cfb128, key))),

        _ => None
    }
}

#[test]
fn test_get_cipher() {
    let key = "PASSWORD";
    let c = with_name(CIPHER_AES_128_CFB, key.as_bytes()).unwrap();
    let message = "HELLO WORLD";

    let encrypted_msg = c.encrypt(message.as_bytes());
    let decrypted_msg = c.decrypt(encrypted_msg.as_slice());

    assert!(message.as_bytes() == decrypted_msg.as_slice());
}
