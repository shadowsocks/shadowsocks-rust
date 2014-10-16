extern crate libc;

use std::vec::Vec;

pub const CIPHER_AES_128_CFB: &'static str = "aes-128-cfb1";
pub const CIPHER_AES_256_CFB: &'static str = "aes-256-cfb";

struct CipherDef(&'static str, int, int);

const Ciphers: [CipherDef, .. 2] = [
    CipherDef(CIPHER_AES_128_CFB, 16, 16),
    CipherDef(CIPHER_AES_256_CFB, 32, 16),
];

pub enum CipherType {
    CipherAes128Cfb,
    CipherAes256Cfb,
}

#[allow(non_camel_case_types)]
type EVP_CIPHER_CTX = *mut libc::c_void;
#[allow(non_camel_case_types)]
type EVP_CIPHER = *mut libc::c_void;

pub const CIPHER_MODE_ENCRYPT: libc::c_int = 1;
pub const CIPHER_MODE_DECRYPT: libc::c_int = 0;

pub enum CipherMode {
    CipherModeEncrypt,
    CipherModeDecrypt,
}



pub fn cipher_type_from_str(type_string: &str) -> CipherType {
    match type_string {
        CIPHER_AES_128_CFB => CipherAes128Cfb,
        CIPHER_AES_256_CFB => CipherAes256Cfb,
        _ => fail!("Unknown cipher type"),
    }
}

pub struct Crypto {
    cipher: EVP_CIPHER,
    cipher_ctx: EVP_CIPHER_CTX,
}

impl Crypto {
    pub fn new(method: CipherType, key: &str, iv: &str, mode: CipherMode) -> Crypto {
        let cipher = unsafe {
            match method {
                CipherAes128Cfb => EVP_aes_128_cfb128(),
                CipherAes256Cfb => EVP_aes_256_cfb(),
            }
        };
        assert!(!cipher.is_null());
        let cipher_ctx = unsafe { EVP_CIPHER_CTX_new() };

        let op = match mode {
            CipherModeEncrypt => 1,
            CipherModeDecrypt => 0
        };

        unsafe {
            EVP_CipherInit(cipher_ctx, cipher,
                           key.to_c_str().as_ptr(), iv.to_c_str().as_ptr(), op);
        }

        Crypto {
            cipher: cipher,
            cipher_ctx: cipher_ctx,
        }
    }

    pub fn update(&self, data: &[u8]) -> Vec<u8> {
        let pdata: *const u8 = data.as_ptr();
        let datalen: u32 = data.len() as u32;
        let mut reslen: u32 = datalen + (16 as u32);
        let preslen: *mut u32 = &mut reslen;
        let mut res = Vec::from_elem(reslen as uint, 0u8);
        let pres: *mut libc::c_uchar = res.as_mut_ptr();

        unsafe {
            EVP_CipherUpdate(self.cipher_ctx, pres, preslen, pdata, datalen);
        }

        res
    }

    pub fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_CTX_cleanup(self.cipher_ctx);
            EVP_CIPHER_CTX_free(self.cipher_ctx);
        }
    }
}

pub struct Cipher {
    encryptor: Crypto,
    decryptor: Crypto,
}

impl Cipher {
    fn new(method: CipherType, key: &str) -> Cipher {

    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {

    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {

    }
}

#[test]
fn test_encrypt_decrypt() {

}
