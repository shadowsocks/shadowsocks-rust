
use crypto::openssl;

pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub enum CipherType {
    CipherTypeAes128Cfb,
    CipherTypeAes192Cfb,
    CipherTypeAes256Cfb,
}

// pub fn get_cipher_by_name(method: &str, key: &[u8]) -> Cipher {
//     let c = match method {
//         CIPHER_AES_128_CFB =>
//             Some(openssl::OpenSSLCipher::new(CipherTypeAes128Cfb, key)),
//         CIPHER_AES_192_CFB =>
//             Some(openssl::OpenSSLCipher::new(CipherTypeAes192Cfb, key)),
//         CIPHER_AES_256_CFB =>
//             Some(openssl::OpenSSLCipher::new(CipherTypeAes256Cfb, key)),

//         _ => None
//     };

//     c.unwrap()
// }
