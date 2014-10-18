extern crate libc;
extern crate log;

use crypto::cipher::Cipher;
use crypto::cipher;

use std::ptr;

#[allow(non_camel_case_types)]
type EVP_CIPHER_CTX = *const libc::c_void;
#[allow(non_camel_case_types)]
type EVP_CIPHER = *const libc::c_void;
#[allow(non_camel_case_types)]
type EVP_MD = *const libc::c_void;

const CIPHER_MODE_ENCRYPT: libc::c_int = 1;
const CIPHER_MODE_DECRYPT: libc::c_int = 0;

#[allow(dead_code)]
#[link(name="crypto")]
extern {
    fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_cleanup(ctx: EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_free(ctx: EVP_CIPHER_CTX);

    fn EVP_CipherInit(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER,
                      key: *const libc::c_uchar, iv: *const libc::c_uchar, mode: libc::c_int) -> libc::c_int;
    fn EVP_CipherUpdate(ctx: EVP_CIPHER_CTX,
                        outbuf: *mut libc::c_uchar, outlen: *mut libc::c_int,
                        inbuf: *const libc::c_uchar, inlen: libc::c_int) -> libc::c_int;
    fn EVP_CipherFinal(ctx: EVP_CIPHER_CTX, res: *mut libc::c_uchar, len: *mut libc::c_int) -> libc::c_int;

    fn EVP_BytesToKey(cipher: EVP_CIPHER, md: EVP_MD,
                      salt: *const libc::c_uchar, data: *const libc::c_uchar, datal: libc::c_int,
                      count: libc::c_int, key: *mut libc::c_uchar, iv: *mut libc::c_uchar) -> libc::c_int;

    // Ciphers
    fn EVP_aes_128_cfb() -> EVP_CIPHER;
    fn EVP_aes_128_cfb1() -> EVP_CIPHER;
    fn EVP_aes_128_cfb8() -> EVP_CIPHER;
    fn EVP_aes_128_cfb128() -> EVP_CIPHER;
    fn EVP_aes_192_cfb() -> EVP_CIPHER;
    fn EVP_aes_192_cfb1() -> EVP_CIPHER;
    fn EVP_aes_192_cfb8() -> EVP_CIPHER;
    fn EVP_aes_192_cfb128() -> EVP_CIPHER;
    fn EVP_aes_256_cfb() -> EVP_CIPHER;
    fn EVP_aes_256_cfb1() -> EVP_CIPHER;
    fn EVP_aes_256_cfb8() -> EVP_CIPHER;
    fn EVP_aes_256_cfb128() -> EVP_CIPHER;

    // MD
    fn EVP_md5() -> EVP_MD;
    fn EVP_sha() -> EVP_MD;
    fn EVP_sha1() -> EVP_MD;
}

enum CryptoMode {
    CryptoModeDecrypt,
    CryptoModeEncrypt,
}

struct OpenSSLCrypto {
    evp_ctx: EVP_CIPHER_CTX,
    block_size: uint,
    // key_size: uint,
}

impl OpenSSLCrypto {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let (ctx, _, block_size) = unsafe {
            let (cipher, key_size, block_size) = match cipher_type {
                cipher::CipherTypeAes128Cfb => { (EVP_aes_128_cfb(), 16, 16) },
                cipher::CipherTypeAes128Cfb1 => { (EVP_aes_128_cfb1(), 16, 16) },
                cipher::CipherTypeAes128Cfb8 => { (EVP_aes_128_cfb8(), 16, 16) },
                cipher::CipherTypeAes128Cfb128 => { (EVP_aes_128_cfb128(), 16, 16) },

                cipher::CipherTypeAes192Cfb => { (EVP_aes_192_cfb(), 24, 16) },
                cipher::CipherTypeAes192Cfb1 => { (EVP_aes_192_cfb1(), 24, 16) },
                cipher::CipherTypeAes192Cfb8 => { (EVP_aes_192_cfb8(), 24, 16) },
                cipher::CipherTypeAes192Cfb128 => { (EVP_aes_192_cfb128(), 24, 16) },

                cipher::CipherTypeAes256Cfb => { (EVP_aes_256_cfb(), 32, 16) },
                cipher::CipherTypeAes256Cfb1 => { (EVP_aes_256_cfb1(), 32, 16) },
                cipher::CipherTypeAes256Cfb8 => { (EVP_aes_256_cfb8(), 32, 16) },
                cipher::CipherTypeAes256Cfb128 => { (EVP_aes_256_cfb128(), 32, 16) },
            };

            let evp_ctx = EVP_CIPHER_CTX_new();
            assert!(!evp_ctx.is_null());

            let mut pad_key: Vec<u8> = Vec::with_capacity(key_size);
            let mut pad_iv: Vec<u8> = Vec::with_capacity(block_size);

            EVP_BytesToKey(cipher, EVP_md5(), ptr::null(), key.as_ptr(), key.len() as libc::c_int,
                              1, pad_key.as_mut_ptr(), pad_iv.as_mut_ptr());

            let op = match mode {
                CryptoModeEncrypt => 1 as libc::c_int,
                CryptoModeDecrypt => 0 as libc::c_int,
            };

            if EVP_CipherInit(evp_ctx, cipher, pad_key.as_slice().as_ptr(),
                              pad_iv.as_slice().as_ptr(), op) != 1 as libc::c_int {
                EVP_CIPHER_CTX_free(evp_ctx);
                fail!("EVP_CipherInit error");
            }

            (evp_ctx, key_size, block_size)
        };

        OpenSSLCrypto {
            evp_ctx: ctx,
            block_size: block_size,
            // key_size: key_size,
        }
    }

    pub fn cipher(&self, data: &[u8]) -> Vec<u8> {
        unsafe {
            let pdata: *const u8 = data.as_ptr();
            let datalen: libc::c_int = data.len() as libc::c_int;

            let reslen: uint = datalen as uint + self.block_size;
            let mut res = Vec::from_elem(reslen, 0u8);

            let mut len: libc::c_int = 0;
            let pres: *mut u8 = res.as_mut_ptr();

            if EVP_CipherUpdate(self.evp_ctx,
                             pres, &mut len,
                             pdata, datalen) != 1 {
                drop(self);
                fail!("Failed on EVP_CipherUpdate");
            }

            let mut total_length = len;
            if EVP_CipherFinal(self.evp_ctx, pres.offset(len as int), &mut len) != 1 {
                drop(self);
                fail!("Failed on EVP_CipherFinal");
            }

            total_length += len;

            res.truncate(total_length as uint);

            res
        }
    }
}


#[unsafe_destructor]
impl Drop for OpenSSLCrypto {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_CTX_cleanup(self.evp_ctx);
            EVP_CIPHER_CTX_free(self.evp_ctx);
        }
    }
}

pub struct OpenSSLCipher {
    encryptor: OpenSSLCrypto,
    decryptor: OpenSSLCrypto,
}

impl OpenSSLCipher {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8]) -> OpenSSLCipher {
        let enc = OpenSSLCrypto::new(cipher_type, key, CryptoModeEncrypt);
        let dec = OpenSSLCrypto::new(cipher_type, key, CryptoModeDecrypt);

        OpenSSLCipher {
            encryptor: enc,
            decryptor: dec,
        }
    }
}

impl Cipher for OpenSSLCipher {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.encryptor.cipher(data)
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.decryptor.cipher(data)
    }
}

#[test]
fn test_aes() {
    use std::str;

    let message = "hello world";
    let key = "passwordhaha";

    let types = [
        cipher::CipherTypeAes128Cfb,
        cipher::CipherTypeAes128Cfb1,
        cipher::CipherTypeAes128Cfb8,
        cipher::CipherTypeAes128Cfb128,

        cipher::CipherTypeAes192Cfb,
        cipher::CipherTypeAes192Cfb1,
        cipher::CipherTypeAes192Cfb8,
        cipher::CipherTypeAes192Cfb128,

        cipher::CipherTypeAes256Cfb,
        cipher::CipherTypeAes256Cfb1,
        cipher::CipherTypeAes256Cfb8,
        cipher::CipherTypeAes256Cfb128,
    ];

    for t in types.iter() {
        let cipher = OpenSSLCipher::new(*t, key.as_bytes());

        let encrypted_msg = cipher.encrypt(message.as_bytes());
        debug!("ENC {}", encrypted_msg);

        let decrypted_msg = cipher.decrypt(encrypted_msg.as_slice());
        debug!("DEC {}", str::from_utf8(decrypted_msg.as_slice()).unwrap());

        assert!(message.as_bytes() == decrypted_msg.as_slice());
    }
}
