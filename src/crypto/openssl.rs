// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

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

#![allow(dead_code)]

extern crate libc;
extern crate log;
extern crate test;

use crypto::cipher::{Cipher, CipherResult};
use crypto::cipher;

use crypto::digest::Digest;
use crypto::digest;
use crypto::CryptoMode;

use std::ptr;
use std::clone::Clone;
use std::mem::swap;
use std::iter::repeat;

#[allow(non_camel_case_types)]
type EVP_CIPHER_CTX = *const libc::c_void;
#[allow(non_camel_case_types)]
type EVP_CIPHER = *const libc::c_void;
#[allow(non_camel_case_types)]
type EVP_MD_CTX = *mut libc::c_void;
#[allow(non_camel_case_types)]
type EVP_MD = *const libc::c_void;
#[allow(non_camel_case_types)]
type ENGINE = *const libc::c_void;

const CRYPTO_MODE_ENCRYPT: libc::c_int = 1;
const CRYPTO_MODE_DECRYPT: libc::c_int = 0;

#[allow(dead_code)]
#[link(name = "crypto")]
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
    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_128_cfb1() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_128_cfb8() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_128_cfb128() -> EVP_CIPHER;

    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_192_cfb1() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_192_cfb8() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_192_cfb128() -> EVP_CIPHER;

    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_256_cfb1() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_256_cfb8() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-cfb")]
    fn EVP_aes_256_cfb128() -> EVP_CIPHER;

    #[cfg(feature = "cipher-aes-ofb")]
    fn EVP_aes_128_ofb() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-ofb")]
    fn EVP_aes_192_ofb() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-ofb")]
    fn EVP_aes_256_ofb() -> EVP_CIPHER;

    #[cfg(feature = "cipher-aes-ctr")]
    fn EVP_aes_128_ctr() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-ctr")]
    fn EVP_aes_192_ctr() -> EVP_CIPHER;
    #[cfg(feature = "cipher-aes-ctr")]
    fn EVP_aes_256_ctr() -> EVP_CIPHER;

    #[cfg(feature = "cipher-bf-cfb")]
    fn EVP_bf_cfb64() -> EVP_CIPHER;

    #[cfg(feature = "cipher-camellia-cfb")]
    fn EVP_camellia_128_cfb128() -> EVP_CIPHER;
    #[cfg(feature = "cipher-camellia-cfb")]
    fn EVP_camellia_192_cfb128() -> EVP_CIPHER;
    #[cfg(feature = "cipher-camellia-cfb")]
    fn EVP_camellia_256_cfb128() -> EVP_CIPHER;

    #[cfg(feature = "cipher-cast5-cfb")]
    fn EVP_cast5_cfb64() -> EVP_CIPHER;
    #[cfg(feature = "cipher-des-cfb")]
    fn EVP_des_cfb64() -> EVP_CIPHER;
    #[cfg(feature = "cipher-idea-cfb")]
    fn EVP_idea_cfb64() -> EVP_CIPHER;
    #[cfg(feature = "cipher-rc2-cfb")]
    fn EVP_rc2_cfb64() -> EVP_CIPHER;
    #[cfg(feature = "cipher-seed-cfb")]
    fn EVP_seed_cfb128() -> EVP_CIPHER;
    #[cfg(feature = "cipher-rc4")]
    fn EVP_rc4() -> EVP_CIPHER;

    // MD
    fn EVP_MD_CTX_create() -> EVP_MD_CTX;
    fn EVP_MD_CTX_init(ctx: EVP_MD_CTX);
    fn EVP_MD_CTX_cleanup(ctx: EVP_MD_CTX);
    fn EVP_MD_CTX_destroy(ctx: EVP_MD_CTX);
    fn EVP_MD_CTX_copy_ex(out: EVP_MD_CTX, ctx_in: EVP_MD_CTX) -> libc::c_int;
    fn EVP_DigestInit_ex(ctx: EVP_MD_CTX, md_type: EVP_MD, engine: ENGINE) -> libc::c_int;
    fn EVP_DigestUpdate(ctx: EVP_MD_CTX, d: *const libc::c_void, cnt: libc::size_t) -> libc::c_int;
    fn EVP_DigestFinal_ex(ctx: EVP_MD_CTX, md: *mut libc::c_uchar, s: *mut libc::size_t);

    fn EVP_md5() -> EVP_MD;
    fn EVP_sha() -> EVP_MD;
    fn EVP_sha1() -> EVP_MD;
}

pub struct OpenSSLDigest {
    md_ctx: EVP_MD_CTX,
    digest_len: usize,
}

impl OpenSSLDigest {
    pub fn new(t: digest::DigestType) -> OpenSSLDigest {
        let ctx = unsafe {
            let md_ctx = EVP_MD_CTX_create();
            assert!(!md_ctx.is_null());
            EVP_MD_CTX_init(md_ctx);
            md_ctx
        };

        let dlen = unsafe {
            let (md, len) = OpenSSLDigest::get_md(t);
            EVP_DigestInit_ex(ctx, md, ptr::null());
            len
        };

        OpenSSLDigest {
            md_ctx: ctx,
            digest_len: dlen,
        }
    }

    fn get_md(t: digest::DigestType) -> (EVP_MD, usize) {
        unsafe {
            match t {
                digest::DigestType::Md5 => { (EVP_md5(), 16us) },
                digest::DigestType::Sha => { (EVP_sha(), 20us) },
                digest::DigestType::Sha1 => { (EVP_sha1(), 20us) },
            }
        }
    }
}

impl Digest for OpenSSLDigest {
    fn update(&mut self, data: &[u8]) {
        unsafe {
            if EVP_DigestUpdate(self.md_ctx, data.as_ptr() as *const libc::c_void, data.len() as libc::size_t)
                    != 1 as libc::c_int {
                panic!("Failed to call EVP_DigestUpdate");
            }
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut dig = repeat(0u8).take(self.digest_len).collect::<Vec<u8>>();
        unsafe {
            EVP_DigestFinal_ex(self.md_ctx, dig.as_mut_ptr(), ptr::null_mut());
        }
        dig
    }
}

impl Clone for OpenSSLDigest {
    fn clone(&self) -> OpenSSLDigest {
        let ctx = unsafe {
            let md_ctx = EVP_MD_CTX_create();
            assert!(!md_ctx.is_null());
            if EVP_MD_CTX_copy_ex(md_ctx, self.md_ctx) != 1 as libc::c_int {
                EVP_MD_CTX_destroy(md_ctx);
                panic!("Failed to call EVP_MD_CTX_copy_ex");
            }
            md_ctx
        };
        OpenSSLDigest {
            md_ctx: ctx,
            digest_len: self.digest_len,
        }
    }

    fn clone_from(&mut self, source: &OpenSSLDigest) {
        self.md_ctx = unsafe {
            let md_ctx = EVP_MD_CTX_create();
            assert!(!md_ctx.is_null());
            if EVP_MD_CTX_copy_ex(md_ctx, source.md_ctx) != 1 as libc::c_int {
                EVP_MD_CTX_destroy(md_ctx);
                panic!("Failed to call EVP_MD_CTX_copy_ex");
            }
            EVP_MD_CTX_cleanup(self.md_ctx);
            EVP_MD_CTX_destroy(self.md_ctx);
            md_ctx
        };
        self.digest_len = source.digest_len;
    }
}

#[unsafe_destructor]
impl Drop for OpenSSLDigest {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_cleanup(self.md_ctx);
            EVP_MD_CTX_destroy(self.md_ctx);
        }
    }
}

struct OpenSSLCrypto {
    evp_ctx: EVP_CIPHER_CTX,
    block_size: usize,
    // key_size: usize,
    cipher_type: cipher::CipherType,
    key: Vec<u8>,
    iv: Vec<u8>,
    mode: CryptoMode,
}

impl OpenSSLCrypto {
    pub fn bytes_to_key(cipher_type: cipher::CipherType, key: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (cipher, key_size, block_size) = OpenSSLCrypto::get_cipher(cipher_type);
        let mut pad_key: Vec<u8> = repeat(0u8).take(key_size).collect();
        let mut pad_iv: Vec<u8> = repeat(0u8).take(block_size).collect();

        unsafe {
            EVP_BytesToKey(cipher, EVP_md5(), ptr::null(), key.as_ptr(), key.len() as libc::c_int,
                              1, pad_key.as_mut_ptr(), pad_iv.as_mut_ptr());
        }

        (pad_key, pad_iv)
    }

    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let (ctx, _, block_size) = unsafe {
            let (cipher, key_size, block_size) = OpenSSLCrypto::get_cipher(cipher_type);

            // assert!(iv.len() >= block_size);

            let evp_ctx = EVP_CIPHER_CTX_new();
            assert!(!evp_ctx.is_null());

            let op = match mode {
                CryptoMode::Encrypt => CRYPTO_MODE_ENCRYPT,
                CryptoMode::Decrypt => CRYPTO_MODE_DECRYPT,
            };

            if EVP_CipherInit_ex(evp_ctx, cipher, ptr::null(), key.as_ptr(),
                              iv.as_ptr(), op) != 1 as libc::c_int {
                EVP_CIPHER_CTX_free(evp_ctx);
                panic!("EVP_CipherInit error");
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

    pub fn get_cipher(cipher_type: cipher::CipherType) -> (EVP_CIPHER, usize, usize) {
        unsafe {
            match cipher_type {
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb => { (EVP_aes_128_cfb128(), 16, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb1 => { (EVP_aes_128_cfb1(), 16, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb8 => { (EVP_aes_128_cfb8(), 16, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb128 => { (EVP_aes_128_cfb128(), 16, 16) },

                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb => { (EVP_aes_192_cfb128(), 24, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb1 => { (EVP_aes_192_cfb1(), 24, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb8 => { (EVP_aes_192_cfb8(), 24, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb128 => { (EVP_aes_192_cfb128(), 24, 16) },

                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb => { (EVP_aes_256_cfb128(), 32, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb1 => { (EVP_aes_256_cfb1(), 32, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb8 => { (EVP_aes_256_cfb8(), 32, 16) },
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb128 => { (EVP_aes_256_cfb128(), 32, 16) },

                #[cfg(feature = "cipher-aes-ofb")]
                cipher::CipherType::Aes128Ofb => { (EVP_aes_128_ofb(), 16, 16) },
                #[cfg(feature = "cipher-aes-ofb")]
                cipher::CipherType::Aes192Ofb => { (EVP_aes_192_ofb(), 24, 16) },
                #[cfg(feature = "cipher-aes-ofb")]
                cipher::CipherType::Aes256Ofb => { (EVP_aes_256_ofb(), 32, 16) },

                #[cfg(feature = "cipher-aes-ctr")]
                cipher::CipherType::Aes128Ctr => { (EVP_aes_128_ctr(), 16, 16) },
                #[cfg(feature = "cipher-aes-ctr")]
                cipher::CipherType::Aes192Ctr => { (EVP_aes_192_ctr(), 24, 16) },
                #[cfg(feature = "cipher-aes-ctr")]
                cipher::CipherType::Aes256Ctr => { (EVP_aes_256_ctr(), 32, 16) },

                #[cfg(feature = "cipher-bf-cfb")]
                cipher::CipherType::BfCfb => { (EVP_bf_cfb64(), 16, 8) },

                #[cfg(feature = "cipher-camellia-cfb")]
                cipher::CipherType::Camellia128Cfb => { (EVP_camellia_128_cfb128(), 16, 16) },
                #[cfg(feature = "cipher-camellia-cfb")]
                cipher::CipherType::Camellia192Cfb => { (EVP_camellia_192_cfb128(), 24, 16) },
                #[cfg(feature = "cipher-camellia-cfb")]
                cipher::CipherType::Camellia256Cfb => { (EVP_camellia_256_cfb128(), 32, 16) },

                #[cfg(feature = "cipher-cast5-cfb")]
                cipher::CipherType::Cast5Cfb => { (EVP_cast5_cfb64(), 16, 8) },
                #[cfg(feature = "cipher-des-cfb")]
                cipher::CipherType::DesCfb => { (EVP_des_cfb64(), 8, 8) },
                #[cfg(feature = "cipher-idea-cfb")]
                cipher::CipherType::IdeaCfb => { (EVP_idea_cfb64(), 16, 8) },
                #[cfg(feature = "cipher-rc2-cfb")]
                cipher::CipherType::Rc2Cfb => { (EVP_rc2_cfb64(), 16, 8) },
                #[cfg(feature = "cipher-seed-cfb")]
                cipher::CipherType::SeedCfb => { (EVP_seed_cfb128(), 16, 16) },
                #[cfg(feature = "cipher-rc4")]
                cipher::CipherType::Rc4 => { (EVP_rc4(), 16, 16) },
                #[cfg(feature = "cipher-rc4")]
                cipher::CipherType::Rc4Md5 => { (EVP_rc4(), 16, 16) },

                _ => { panic!("Unsupported cipher type of OpenSSL") },
            }
        }
    }

    pub fn update(&self, data: &[u8]) -> CipherResult<Vec<u8>> {
        let pdata: *const u8 = data.as_ptr();
        let datalen: libc::c_int = data.len() as libc::c_int;

        let mut out = Vec::with_capacity(data.len() + self.block_size);
        unsafe { out.set_len(data.len() + self.block_size); }

        let mut len: libc::c_int = 0;
        let pres: *mut u8 = out.as_mut_ptr();

        unsafe {
            if EVP_CipherUpdate(self.evp_ctx,
                             pres, &mut len,
                             pdata, datalen) != 1 {

                return Err(cipher::Error {
                    kind: cipher::ErrorKind::OpenSSLError,
                    desc: "Failed on EVP_CipherUpdate",
                    detail: None,
                });
            }
        }

        out.truncate(len as usize);
        Ok(out)
    }

    pub fn finalize(&self) -> CipherResult<Vec<u8>> {
        let mut len: libc::c_int = 0;
        let mut out = Vec::with_capacity(self.block_size);
        unsafe { out.set_len(self.block_size) }

        unsafe {
            if EVP_CipherFinal(self.evp_ctx, out.as_mut_ptr(), &mut len) != 1 {
                return Err(cipher::Error {
                    kind: cipher::ErrorKind::OpenSSLError,
                    desc: "Failed on EVP_CipherFinal",
                    detail: None,
                });
            }
        }

        out.truncate(len as usize);
        Ok(out)
    }
}

impl Clone for OpenSSLCrypto {
    fn clone(&self) -> OpenSSLCrypto {
        OpenSSLCrypto::new(self.cipher_type.clone(), self.key.as_slice(), self.iv.as_slice(), self.mode.clone())
    }

    fn clone_from(&mut self, source: &OpenSSLCrypto) {
        let mut new_cipher = OpenSSLCrypto::new(source.cipher_type.clone(),
                                  source.key.as_slice(),
                                  source.iv.as_slice(),
                                  source.mode.clone());
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
/// use shadowsocks::crypto::CryptoMode;
/// use shadowsocks::crypto::cipher;
/// use shadowsocks::crypto::openssl::OpenSSLCipher;
/// use shadowsocks::crypto::cipher::Cipher;
///
/// let mut enc = OpenSSLCipher::new(cipher::CipherType::Aes128Cfb, "password".as_bytes(), CryptoMode::Encrypt);
/// let mut dec = OpenSSLCipher::new(cipher::CipherType::Aes128Cfb, "password".as_bytes(), CryptoMode::Decrypt);
/// let message = "hello world";
/// let encrypted_message = enc.update(message.as_bytes()).unwrap();
/// let decrypted_message = dec.update(encrypted_message.as_slice()).unwrap();
///
/// assert!(decrypted_message.as_slice() == message.as_bytes());
/// ```
#[derive(Clone)]
pub struct OpenSSLCipher {
    worker: Option<OpenSSLCrypto>,
    cipher_type: cipher::CipherType,
    mode: CryptoMode,
    key: Vec<u8>,
    iv_cache: Vec<u8>
}

impl OpenSSLCipher {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], mode: CryptoMode) -> OpenSSLCipher {
        OpenSSLCipher {
            worker: None,//OpenSSLCrypto::new(cipher_type, key.as_slice(), iv.as_slice(), mode),
            cipher_type: cipher_type,
            mode: mode,
            key: key.to_vec(),
            iv_cache: Vec::new(),
        }
    }
}

impl Cipher for OpenSSLCipher {
    fn update(&mut self, data: &[u8]) -> CipherResult<Vec<u8>> {
        match self.worker {
            Some(ref worker) => worker.update(data),
            None => {
                match self.mode {
                    CryptoMode::Encrypt => {
                        let (key, mut iv) = {
                            let (key, iv) = OpenSSLCrypto::bytes_to_key(self.cipher_type,
                                                                        self.key.as_slice());

                            match self.cipher_type {
                                #[cfg(feature = "cipher-rc4")]
                                cipher::CipherType::Rc4Md5 => {
                                    let mut md5_digest = OpenSSLDigest::new(digest::DigestType::Md5);
                                    md5_digest.update(key.as_slice());
                                    md5_digest.update(iv.as_slice());
                                    (md5_digest.digest(), iv)
                                },
                                _ => {
                                    (key, iv)
                                }
                            }
                        };

                        let worker = OpenSSLCrypto::new(self.cipher_type,
                                                        key.as_slice(),
                                                        iv.as_slice(),
                                                        self.mode);
                        let encrypted_data = try!(worker.update(data));
                        iv.push_all(encrypted_data.as_slice());

                        self.worker = Some(worker);

                        Ok(iv)
                    },
                    CryptoMode::Decrypt => {
                        let required_iv_len = self.cipher_type.block_size() - self.iv_cache.len();
                        if required_iv_len <= data.len() {
                            let (remain_iv, realdata) = data.split_at(required_iv_len);
                            self.iv_cache.push_all(remain_iv);

                            let (pad_key, _) = OpenSSLCrypto::bytes_to_key(
                                    self.cipher_type,
                                    self.key.as_slice()
                                );

                            let key = match self.cipher_type {
                                #[cfg(feature = "cipher-rc4")]
                                cipher::CipherType::Rc4Md5 => {
                                    let mut md5_digest = OpenSSLDigest::new(digest::DigestType::Md5);
                                    md5_digest.update(pad_key.as_slice());
                                    md5_digest.update(self.iv_cache.as_slice());
                                    md5_digest.digest()
                                },
                                _ => {
                                    pad_key
                                }
                            };

                            self.worker = Some(OpenSSLCrypto::new(self.cipher_type,
                                                                  key.as_slice(),
                                                                  self.iv_cache.as_slice(),
                                                                  self.mode));
                            self.iv_cache.clear();
                            self.worker.as_ref().unwrap().update(realdata)
                        } else {
                            self.iv_cache.push_all(data);

                            Ok(Vec::new())
                        }
                    }
                }
            }
        }
    }

    fn finalize(&mut self) -> CipherResult<Vec<u8>> {
        match self.worker {
            Some(ref worker) => worker.finalize(),
            None => Ok(Vec::new())
        }
    }
}

unsafe impl Send for OpenSSLCipher {}

#[test]
fn test_default_ciphers() {

    let message = "hello world";
    let key = "passwordhaha";

    println!("ORIGINAL {:?}", message.as_bytes());

    let types = [
        cipher::CipherType::Aes128Cfb,
        cipher::CipherType::Aes128Cfb1,
        cipher::CipherType::Aes128Cfb8,
        cipher::CipherType::Aes128Cfb128,

        cipher::CipherType::Aes192Cfb,
        cipher::CipherType::Aes192Cfb1,
        cipher::CipherType::Aes192Cfb8,
        cipher::CipherType::Aes192Cfb128,

        cipher::CipherType::Aes256Cfb,
        cipher::CipherType::Aes256Cfb1,
        cipher::CipherType::Aes256Cfb8,
        cipher::CipherType::Aes256Cfb128,

        cipher::CipherType::Aes128Ofb,
        cipher::CipherType::Aes192Ofb,
        cipher::CipherType::Aes256Ofb,

        cipher::CipherType::BfCfb,

        cipher::CipherType::Cast5Cfb,
        cipher::CipherType::DesCfb,
        cipher::CipherType::Rc2Cfb,
    ];

    for t in types.iter() {
        let mut enc = OpenSSLCipher::new(*t, key.as_bytes(), CryptoMode::Encrypt);
        let mut dec = OpenSSLCipher::new(*t, key.as_bytes(), CryptoMode::Decrypt);

        let mut encrypted_msg = enc.update(message.as_bytes()).unwrap();
        encrypted_msg.push_all(enc.finalize().unwrap().as_slice());
        println!("ENC {:?}", encrypted_msg);

        let mut decrypted_msg = dec.update(encrypted_msg.as_slice()).unwrap();
        decrypted_msg.push_all(dec.finalize().unwrap().as_slice());
        println!("DEC {:?}", decrypted_msg.as_slice());

        assert!(message.as_bytes() == decrypted_msg.as_slice());
    }
}

#[bench]
fn bench_openssl_default_cipher_encrypt(b: &mut test::Bencher) {
    use std::rand::random;

    let msg_size: usize = 0xffff;

    let mut test_data = Vec::new();
    for _ in range::<usize>(0, 100) {
        let msg = range(0, msg_size).map(|_| random::<u8>()).collect::<Vec<u8>>();
        let key = range(1, random::<usize>() % 63).map(|_| random::<u8>()).collect::<Vec<u8>>();

        test_data.push((msg, key));
    }

    b.iter(|| {
        let (ref msg, ref key) = test_data[random::<usize>() % test_data.len()];

        let mut enc = OpenSSLCipher::new(cipher::CipherType::Aes256Cfb, key.as_slice(), CryptoMode::Encrypt);
        enc.update(msg.as_slice()).unwrap();
    });
    b.bytes = msg_size as u64;
}

#[bench]
fn bench_openssl_default_cipher_decrypt(b: &mut test::Bencher) {
    use std::rand::random;

    let msg_size: usize = 0xffff;
    let mut test_data = Vec::new();
    for _ in range::<usize>(0, 100) {
        let msg = range(0, msg_size).map(|_| random::<u8>()).collect::<Vec<u8>>();
        let key = range(1, random::<usize>() % 63).map(|_| random::<u8>()).collect::<Vec<u8>>();
        let mut cipher = OpenSSLCipher::new(cipher::CipherType::Aes256Cfb, key.as_slice(), CryptoMode::Encrypt);
        let encrypted_msg = cipher.update(msg.as_slice()).unwrap();
        test_data.push((key, encrypted_msg));
    }

    b.iter(|| {
        let (ref key, ref encrypted_msg) = test_data[random::<usize>() % test_data.len()];
        let mut cipher = OpenSSLCipher::new(cipher::CipherType::Aes256Cfb, key.as_slice(), CryptoMode::Decrypt);
        cipher.update(encrypted_msg.as_slice()).unwrap();
    });
    b.bytes = msg_size as u64;
}
