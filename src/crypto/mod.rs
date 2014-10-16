extern crate libc;

pub mod cipher;
pub mod openssl;

pub const CIPHER_AES_128_CFB: &'static str = "aes-128-cfb";
pub const CIPHER_AES_192_CFB: &'static str = "aes-192-cfb";
pub const CIPHER_AES_256_CFB: &'static str = "aes-256-cfb";
