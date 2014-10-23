// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Cipher defined with Rust binding for libcrypto (OpenSSL)

extern crate libc;
extern crate log;

use crypto::cipher::Cipher;
use crypto::cipher;

use std::ptr;
use std::clone::Clone;
use std::mem::swap;

#[allow(non_camel_case_types)]
type EVP_CIPHER_CTX = *const libc::c_void;
#[allow(non_camel_case_types)]
type EVP_CIPHER = *const libc::c_void;
#[allow(non_camel_case_types)]
type EVP_MD = *const libc::c_void;
#[allow(non_camel_case_types)]
type ENGINE = *const libc::c_void;

const CRYPTO_MODE_ENCRYPT: libc::c_int = 1;
const CRYPTO_MODE_DECRYPT: libc::c_int = 0;

#[allow(dead_code)]
#[link(name="crypto")]
extern {
    fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_cleanup(ctx: EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_free(ctx: EVP_CIPHER_CTX);

    fn EVP_CipherInit_ex(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER, engine: ENGINE,
                      key: *const libc::c_uchar, iv: *const libc::c_uchar, mode: libc::c_int) -> libc::c_int;
    fn EVP_CipherUpdate(ctx: EVP_CIPHER_CTX,
                        outbuf: *mut libc::c_uchar, outlen: *mut libc::c_int,
                        inbuf: *const libc::c_uchar, inlen: libc::c_int) -> libc::c_int;
    fn EVP_CipherFinal(ctx: EVP_CIPHER_CTX, res: *mut libc::c_uchar, len: *mut libc::c_int) -> libc::c_int;

    fn EVP_BytesToKey(cipher: EVP_CIPHER, md: EVP_MD,
                      salt: *const libc::c_uchar, data: *const libc::c_uchar, datal: libc::c_int,
                      count: libc::c_int, key: *mut libc::c_uchar, iv: *mut libc::c_uchar) -> libc::c_int;

    // Ciphers
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_128_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_128_cfb1() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_128_cfb8() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_128_cfb128() -> EVP_CIPHER;

    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_192_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_192_cfb1() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_192_cfb8() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_192_cfb128() -> EVP_CIPHER;

    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_256_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_256_cfb1() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_256_cfb8() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-cfb")]
    fn EVP_aes_256_cfb128() -> EVP_CIPHER;

    #[cfg(feature="cipher-aes-ofb")]
    fn EVP_aes_128_ofb() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-ofb")]
    fn EVP_aes_192_ofb() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-ofb")]
    fn EVP_aes_256_ofb() -> EVP_CIPHER;

    #[cfg(feature="cipher-aes-ctr")]
    fn EVP_aes_128_ctr() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-ctr")]
    fn EVP_aes_192_ctr() -> EVP_CIPHER;
    #[cfg(feature="cipher-aes-ctr")]
    fn EVP_aes_256_ctr() -> EVP_CIPHER;

    #[cfg(feature="cipher-bf-cfb")]
    fn EVP_bf_cfb() -> EVP_CIPHER;

    #[cfg(feature="cipher-camellia-cfb")]
    fn EVP_camellia_128_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-camellia-cfb")]
    fn EVP_camellia_192_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-camellia-cfb")]
    fn EVP_camellia_256_cfb() -> EVP_CIPHER;

    #[cfg(feature="cipher-cast5-cfb")]
    fn EVP_cast5_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-des-cfb")]
    fn EVP_des_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-idea-cfb")]
    fn EVP_idea_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-rc2-cfb")]
    fn EVP_rc2_cfb() -> EVP_CIPHER;
    #[cfg(feature="cipher-rc4-hmac-md5")]
    fn EVP_rc4_hmac_md5() -> EVP_CIPHER;
    #[cfg(feature="cipher-seed-cfb")]
    fn EVP_seed_cfb() -> EVP_CIPHER;

    // MD
    fn EVP_md5() -> EVP_MD;
    fn EVP_sha() -> EVP_MD;
    fn EVP_sha1() -> EVP_MD;
}

/// This two modes will be converted into the last parameter of `EVP_CipherInit_ex`.
enum CryptoMode {
    CryptoModeDecrypt,
    CryptoModeEncrypt,
}

struct OpenSSLCrypto {
    evp_ctx: EVP_CIPHER_CTX,
    block_size: uint,
    // key_size: uint,
    cipher_type: cipher::CipherType,
    key: Vec<u8>,
    iv: Vec<u8>,
    mode: CryptoMode,
}

impl OpenSSLCrypto {
    pub fn bytes_to_key(cipher_type: cipher::CipherType, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (cipher, key_size, block_size) = OpenSSLCrypto::get_cipher(cipher_type);
        let mut pad_key: Vec<u8> = Vec::from_elem(key_size, 0u8);
        let mut pad_iv: Vec<u8> = Vec::from_elem(block_size, 0u8);

        unsafe {
            EVP_BytesToKey(cipher, EVP_md5(), ptr::null(), key.as_ptr(), key.len() as libc::c_int,
                              1, pad_key.as_mut_ptr(), pad_iv.as_mut_ptr());
        }

        (pad_key, pad_iv)
    }

    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let (ctx, _, block_size) = unsafe {
            let (cipher, key_size, block_size) = OpenSSLCrypto::get_cipher(cipher_type);

            assert!(iv.len() >= block_size);

            let evp_ctx = EVP_CIPHER_CTX_new();
            assert!(!evp_ctx.is_null());

            let op = match mode {
                CryptoModeEncrypt => CRYPTO_MODE_ENCRYPT,
                CryptoModeDecrypt => CRYPTO_MODE_DECRYPT,
            };

            if EVP_CipherInit_ex(evp_ctx, cipher, ptr::null(), key.as_ptr(),
                              iv.as_ptr(), op) != 1 as libc::c_int {
                EVP_CIPHER_CTX_free(evp_ctx);
                fail!("EVP_CipherInit error");
            }

            (evp_ctx, key_size, block_size)
        };

        OpenSSLCrypto {
            evp_ctx: ctx,
            block_size: block_size,
            // key_size: key_size,
            cipher_type: cipher_type,
            key: key.to_vec(),
            iv: iv.to_vec(),
            mode: mode,
        }
    }

    pub fn get_cipher(cipher_type: cipher::CipherType) -> (EVP_CIPHER, uint, uint) {
        unsafe {
            match cipher_type {
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes128Cfb => { (EVP_aes_128_cfb(), 16, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes128Cfb1 => { (EVP_aes_128_cfb1(), 16, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes128Cfb8 => { (EVP_aes_128_cfb8(), 16, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes128Cfb128 => { (EVP_aes_128_cfb128(), 16, 16) },

                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes192Cfb => { (EVP_aes_192_cfb(), 24, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes192Cfb1 => { (EVP_aes_192_cfb1(), 24, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes192Cfb8 => { (EVP_aes_192_cfb8(), 24, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes192Cfb128 => { (EVP_aes_192_cfb128(), 24, 16) },

                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes256Cfb => { (EVP_aes_256_cfb(), 32, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes256Cfb1 => { (EVP_aes_256_cfb1(), 32, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes256Cfb8 => { (EVP_aes_256_cfb8(), 32, 16) },
                #[cfg(feature="cipher-aes-cfb")]
                cipher::CipherTypeAes256Cfb128 => { (EVP_aes_256_cfb128(), 32, 16) },

                #[cfg(feature="cipher-aes-ofb")]
                cipher::CipherTypeAes128Ofb => { (EVP_aes_128_ofb(), 16, 16) },
                #[cfg(feature="cipher-aes-ofb")]
                cipher::CipherTypeAes192Ofb => { (EVP_aes_192_ofb(), 24, 16) },
                #[cfg(feature="cipher-aes-ofb")]
                cipher::CipherTypeAes256Ofb => { (EVP_aes_256_ofb(), 32, 16) },

                #[cfg(feature="cipher-aes-ctr")]
                cipher::CipherTypeAes128Ctr => { (EVP_aes_128_ctr(), 16, 16) },
                #[cfg(feature="cipher-aes-ctr")]
                cipher::CipherTypeAes192Ctr => { (EVP_aes_192_ctr(), 24, 16) },
                #[cfg(feature="cipher-aes-ctr")]
                cipher::CipherTypeAes256Ctr => { (EVP_aes_256_ctr(), 32, 16) },

                #[cfg(feature="cipher-bf-cfb")]
                cipher::CipherTypeBfCfb => { (EVP_bf_cfb(), 16, 8) },

                #[cfg(feature="cipher-camellia-cfb")]
                cipher::CipherTypeCamellia128Cfb => { (EVP_camellia_128_cfb(), 16, 16) },
                #[cfg(feature="cipher-camellia-cfb")]
                cipher::CipherTypeCamellia192Cfb => { (EVP_camellia_192_cfb(), 24, 16) },
                #[cfg(feature="cipher-camellia-cfb")]
                cipher::CipherTypeCamellia256Cfb => { (EVP_camellia_256_cfb(), 32, 16) },

                #[cfg(feature="cipher-cast5-cfb")]
                cipher::CipherTypeCast5Cfb => { (EVP_cast5_cfb(), 16, 8) },
                #[cfg(feature="cipher-des-cfb")]
                cipher::CipherTypeDesCfb => { (EVP_des_cfb(), 8, 8) },
                #[cfg(feature="cipher-idea-cfb")]
                cipher::CipherTypeIdeaCfb => { (EVP_idea_cfb(), 16, 8) },
                #[cfg(feature="cipher-rc2-cfb")]
                cipher::CipherTypeRc2Cfb => { (EVP_rc2_cfb(), 16, 8) },
                #[cfg(feature="cipher-rc4-hmac-md5")]
                cipher::CipherTypeRc4HmacMd5 => { (EVP_rc4_hmac_md5(), 16, 0) },
                #[cfg(feature="cipher-seed-cfb")]
                cipher::CipherTypeSeedCfb => { (EVP_seed_cfb(), 16, 16) },

                cipher::CipherTypeUnknown => { (ptr::null(), 0, 0) },
            }
        }
    }

    pub fn update(&self, data: &[u8]) -> Vec<u8> {
        let pdata: *const u8 = data.as_ptr();
        let datalen: libc::c_int = data.len() as libc::c_int;

        let reslen: uint = datalen as uint + self.block_size;
        let mut res = Vec::from_elem(reslen, 0u8);

        let mut len: libc::c_int = 0;
        let pres: *mut u8 = res.as_mut_ptr();

        let mut total_length: libc::c_int;
        unsafe {
            if EVP_CipherUpdate(self.evp_ctx,
                             pres, &mut len,
                             pdata, datalen) != 1 {
                drop(self);
                fail!("Failed on EVP_CipherUpdate");
            }

            total_length = len;
            if EVP_CipherFinal(self.evp_ctx, pres.offset(len as int), &mut len) != 1 {
                drop(self);
                fail!("Failed on EVP_CipherFinal");
            }

            total_length += len;
        }

        res.truncate(total_length as uint);
        res
    }
}

impl Clone for OpenSSLCrypto {
    fn clone(&self) -> OpenSSLCrypto {
        OpenSSLCrypto::new(self.cipher_type, self.key.as_slice(), self.iv.as_slice(), self.mode)
    }

    fn clone_from(&mut self, source: &OpenSSLCrypto) {
        let mut new_cipher = OpenSSLCrypto::new(source.cipher_type,
                                  source.key.as_slice(),
                                  source.iv.as_slice(),
                                  source.mode);
        swap(&mut self.evp_ctx, &mut new_cipher.evp_ctx);
        swap(&mut self.block_size, &mut new_cipher.block_size);
        swap(&mut self.cipher_type, &mut new_cipher.cipher_type);
        swap(&mut self.key, &mut new_cipher.key);
        swap(&mut self.iv, &mut new_cipher.iv);
        swap(&mut self.mode, &mut new_cipher.mode);
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

/// The Cipher binding for OpenSSL's `libcrypto`.
///
/// It should be noticed that the decipher needs to read the iv (initialization vector)
/// from the first call of `decrypt`. So the cipher will have to insert the iv into
/// the front of the encrypted data.
///
/// *Note: This behavior works just the same as the official version of shadowsocks.*
///
/// ```rust
/// use shadowsocks::crypto::cipher;
/// use shadowsocks::crypto::openssl::OpenSSLCipher;
/// use shadowsocks::crypto::cipher::Cipher;
///
/// let mut cipher = OpenSSLCipher::new(cipher::CipherTypeAes128Cfb, "password".as_bytes());
/// let message = "hello world";
/// let encrypted_message = cipher.encrypt(message.as_bytes());
/// let decrypted_message = cipher.decrypt(encrypted_message.as_slice());
///
/// assert!(decrypted_message.as_slice() == message.as_bytes());
/// ```
#[deriving(Clone)]
pub struct OpenSSLCipher {
    encryptor: Option<OpenSSLCrypto>,
    decryptor: Option<OpenSSLCrypto>,
    key: Vec<u8>,
    cipher_type: cipher::CipherType,
}

impl OpenSSLCipher {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8]) -> OpenSSLCipher {
        OpenSSLCipher {
            encryptor: None,
            decryptor: None,
            key: key.to_vec(),
            cipher_type: cipher_type,
        }
    }
}

impl Cipher for OpenSSLCipher {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        match self.encryptor {
            Some(ref encryptor) => { encryptor.update(data) },
            None => {
                let (key, mut iv) = OpenSSLCrypto::bytes_to_key(
                                    self.cipher_type,
                                    self.key.as_slice()
                                );

                let encryptor = OpenSSLCrypto::new(self.cipher_type, key.as_slice(), iv.as_slice(), CryptoModeEncrypt);
                self.encryptor = Some(encryptor);

                let encrypted_data = self.encryptor.as_ref().unwrap().update(data);
                iv.push_all(encrypted_data.as_slice());

                // Send the IV before encrypted data
                iv
            }
        }
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        match self.decryptor {
            Some(ref decryptor) => { decryptor.update(data) },
            None => {
                let (key, iv) = OpenSSLCrypto::bytes_to_key(
                                    self.cipher_type,
                                    self.key.as_slice()
                                );

                // Get the begining IV from the data
                let expected_iv_len = iv.len();
                let (real_iv, data) = data.split_at(expected_iv_len);

                let decryptor = OpenSSLCrypto::new(self.cipher_type, key.as_slice(), real_iv, CryptoModeDecrypt);
                self.decryptor = Some(decryptor);

                self.decryptor.as_ref().unwrap().update(data)
            }
        }
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

        cipher::CipherTypeAes128Ofb,
        cipher::CipherTypeAes192Ofb,
        cipher::CipherTypeAes256Ofb,

        cipher::CipherTypeBfCfb,

        cipher::CipherTypeCast5Cfb,
        cipher::CipherTypeDesCfb,
        cipher::CipherTypeRc2Cfb,
    ];

    for t in types.iter() {
        let mut cipher = OpenSSLCipher::new(*t, key.as_bytes());

        let encrypted_msg = cipher.encrypt(message.as_bytes());
        debug!("ENC {}", encrypted_msg);

        let decrypted_msg = cipher.decrypt(encrypted_msg.as_slice());
        debug!("DEC {}", str::from_utf8(decrypted_msg.as_slice()).unwrap());

        assert!(message.as_bytes() == decrypted_msg.as_slice());
    }
}
