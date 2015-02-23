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

use crypto::cipher::{Cipher, CipherType, CipherResult};
use crypto::cipher;

use crypto::digest::Digest;
use crypto::digest;
use crypto::CryptoMode;

use std::ptr;
use std::clone::Clone;

mod ffi {
    extern crate libc;

    #[allow(non_camel_case_types)]
    pub type EVP_CIPHER_CTX = libc::c_void;
    #[allow(non_camel_case_types)]
    pub type EVP_CIPHER = libc::c_void;
    #[allow(non_camel_case_types)]
    pub type EVP_MD_CTX = libc::c_void;
    #[allow(non_camel_case_types)]
    pub type EVP_MD = libc::c_void;
    #[allow(non_camel_case_types)]
    pub type ENGINE = libc::c_void;

    pub const CRYPTO_MODE_ENCRYPT: libc::c_int = 1;
    pub const CRYPTO_MODE_DECRYPT: libc::c_int = 0;

    #[allow(dead_code)]
    #[link(name = "crypto")]
    extern {
        pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
        pub fn EVP_CIPHER_CTX_cleanup(ctx: *mut EVP_CIPHER_CTX);
        pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
        pub fn EVP_CIPHER_CTX_copy(out: *mut EVP_CIPHER_CTX, ctx_in: *const EVP_CIPHER_CTX) -> libc::c_int;

        pub fn EVP_CipherInit_ex(ctx: *mut EVP_CIPHER_CTX, evp: *const EVP_CIPHER, engine: *mut ENGINE,
                                 key: *const libc::c_uchar, iv: *const libc::c_uchar, mode: libc::c_int)
            -> libc::c_int;
        pub fn EVP_CipherUpdate(ctx: *mut EVP_CIPHER_CTX,
                                outbuf: *mut libc::c_uchar, outlen: *mut libc::c_int,
                                inbuf: *const libc::c_uchar, inlen: libc::c_int) -> libc::c_int;
        pub fn EVP_CipherFinal(ctx: *mut EVP_CIPHER_CTX, res: *mut libc::c_uchar, len: *mut libc::c_int)
            -> libc::c_int;

        // Ciphers
        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_128_cfb1() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_128_cfb8() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_128_cfb128() -> *const EVP_CIPHER;

        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_192_cfb1() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_192_cfb8() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_192_cfb128() -> *const EVP_CIPHER;

        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_256_cfb1() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_256_cfb8() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-cfb")]
        pub fn EVP_aes_256_cfb128() -> *const EVP_CIPHER;

        #[cfg(feature = "cipher-aes-ofb")]
        pub fn EVP_aes_128_ofb() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-ofb")]
        pub fn EVP_aes_192_ofb() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-ofb")]
        pub fn EVP_aes_256_ofb() -> *const EVP_CIPHER;

        #[cfg(feature = "cipher-aes-ctr")]
        pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-ctr")]
        pub fn EVP_aes_192_ctr() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-aes-ctr")]
        pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;

        #[cfg(feature = "cipher-bf-cfb")]
        pub fn EVP_bf_cfb64() -> *const EVP_CIPHER;

        #[cfg(feature = "cipher-camellia-cfb")]
        pub fn EVP_camellia_128_cfb128() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-camellia-cfb")]
        pub fn EVP_camellia_192_cfb128() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-camellia-cfb")]
        pub fn EVP_camellia_256_cfb128() -> *const EVP_CIPHER;

        #[cfg(feature = "cipher-cast5-cfb")]
        pub fn EVP_cast5_cfb64() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-des-cfb")]
        pub fn EVP_des_cfb64() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-idea-cfb")]
        pub fn EVP_idea_cfb64() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-rc2-cfb")]
        pub fn EVP_rc2_cfb64() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-seed-cfb")]
        pub fn EVP_seed_cfb128() -> *const EVP_CIPHER;
        #[cfg(feature = "cipher-rc4")]
        pub fn EVP_rc4() -> *const EVP_CIPHER;

        // MD
        pub fn EVP_MD_CTX_create() -> *mut EVP_MD_CTX;
        pub fn EVP_MD_CTX_init(ctx: *mut EVP_MD_CTX);
        pub fn EVP_MD_CTX_cleanup(ctx: *mut EVP_MD_CTX);
        pub fn EVP_MD_CTX_destroy(ctx: *mut EVP_MD_CTX);
        pub fn EVP_MD_CTX_copy_ex(out: *mut EVP_MD_CTX, ctx_in: *const EVP_MD_CTX) -> libc::c_int;
        pub fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, md_type: *const EVP_MD, engine: *mut ENGINE) -> libc::c_int;
        pub fn EVP_DigestUpdate(ctx: *const EVP_MD_CTX, d: *const libc::c_void, cnt: libc::size_t) -> libc::c_int;
        pub fn EVP_DigestFinal_ex(ctx: *const EVP_MD_CTX, md: *mut libc::c_uchar, s: *mut libc::size_t);

        pub fn EVP_md5() -> *const EVP_MD;
        pub fn EVP_sha() -> *const EVP_MD;
        pub fn EVP_sha1() -> *const EVP_MD;
    }
}

pub struct OpenSSLDigest {
    md_ctx: *mut ffi::EVP_MD_CTX,
    digest_len: usize,
}

impl OpenSSLDigest {
    pub fn new(t: digest::DigestType) -> OpenSSLDigest {
        let ctx = unsafe {
            let md_ctx = ffi::EVP_MD_CTX_create();
            assert!(!md_ctx.is_null());
            ffi::EVP_MD_CTX_init(md_ctx);
            md_ctx
        };

        let md = OpenSSLDigest::get_md(t);
        unsafe {
            ffi::EVP_DigestInit_ex(ctx, md, ptr::null_mut());
        }

        OpenSSLDigest {
            md_ctx: ctx,
            digest_len: t.digest_len(),
        }
    }

    fn get_md(t: digest::DigestType) -> *const ffi::EVP_MD {
        unsafe {
            match t {
                digest::DigestType::Md5 => ffi::EVP_md5(),
                digest::DigestType::Sha => ffi::EVP_sha(),
                digest::DigestType::Sha1 => ffi::EVP_sha1(),
            }
        }
    }
}

impl Digest for OpenSSLDigest {
    fn update(&mut self, data: &[u8]) {
        unsafe {
            if ffi::EVP_DigestUpdate(self.md_ctx, data.as_ptr() as *const libc::c_void, data.len() as libc::size_t)
                    != 1 as libc::c_int {
                panic!("Failed to call EVP_DigestUpdate");
            }
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        let mut dig = Vec::with_capacity(self.digest_len);
        unsafe {
            dig.set_len(self.digest_len);
            ffi::EVP_DigestFinal_ex(self.md_ctx, dig.as_mut_ptr(), ptr::null_mut());
        }
        dig
    }
}

impl Clone for OpenSSLDigest {
    fn clone(&self) -> OpenSSLDigest {
        let ctx = unsafe {
            let md_ctx = ffi::EVP_MD_CTX_create();
            assert!(!md_ctx.is_null());
            if ffi::EVP_MD_CTX_copy_ex(md_ctx, self.md_ctx) != 1 as libc::c_int {
                ffi::EVP_MD_CTX_destroy(md_ctx);
                panic!("Failed to call EVP_MD_CTX_copy_ex");
            }
            md_ctx
        };
        OpenSSLDigest {
            md_ctx: ctx,
            digest_len: self.digest_len,
        }
    }
}

#[unsafe_destructor]
impl Drop for OpenSSLDigest {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_MD_CTX_cleanup(self.md_ctx);
            ffi::EVP_MD_CTX_destroy(self.md_ctx);
        }
    }
}

unsafe impl Send for OpenSSLDigest {}

pub struct OpenSSLCrypto {
    evp_ctx: *mut ffi::EVP_CIPHER_CTX,
    cipher_type: CipherType,
}

impl OpenSSLCrypto {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCrypto {
        let ctx = unsafe {
            let cipher = OpenSSLCrypto::get_cipher(cipher_type);

            debug_assert!(iv.len() >= cipher_type.block_size());
            debug_assert!(key.len() == cipher_type.key_size());
            let evp_ctx = ffi::EVP_CIPHER_CTX_new();
            assert!(!evp_ctx.is_null());

            let op = match mode {
                CryptoMode::Encrypt => ffi::CRYPTO_MODE_ENCRYPT,
                CryptoMode::Decrypt => ffi::CRYPTO_MODE_DECRYPT,
            };

            if ffi::EVP_CipherInit_ex(evp_ctx, cipher, ptr::null_mut(), key.as_ptr(),
                                      iv.as_ptr(), op) != 1 as libc::c_int {
                ffi::EVP_CIPHER_CTX_free(evp_ctx);
                panic!("EVP_CipherInit error");
            }

            evp_ctx
        };

        OpenSSLCrypto {
            evp_ctx: ctx,
            cipher_type: cipher_type,
        }
    }

    fn get_cipher(cipher_type: cipher::CipherType) -> *const ffi::EVP_CIPHER {
        unsafe {
            match cipher_type {
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb =>        ffi::EVP_aes_128_cfb128(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb1 =>       ffi::EVP_aes_128_cfb1(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb8 =>       ffi::EVP_aes_128_cfb8(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes128Cfb128 =>     ffi::EVP_aes_128_cfb128(),

                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb =>        ffi::EVP_aes_192_cfb128(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb1 =>       ffi::EVP_aes_192_cfb1(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb8 =>       ffi::EVP_aes_192_cfb8(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes192Cfb128 =>     ffi::EVP_aes_192_cfb128(),

                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb =>        ffi::EVP_aes_256_cfb128(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb1 =>       ffi::EVP_aes_256_cfb1(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb8 =>       ffi::EVP_aes_256_cfb8(),
                #[cfg(feature = "cipher-aes-cfb")]
                cipher::CipherType::Aes256Cfb128 =>     ffi::EVP_aes_256_cfb128(),

                #[cfg(feature = "cipher-aes-ofb")]
                cipher::CipherType::Aes128Ofb =>        ffi::EVP_aes_128_ofb(),
                #[cfg(feature = "cipher-aes-ofb")]
                cipher::CipherType::Aes192Ofb =>        ffi::EVP_aes_192_ofb(),
                #[cfg(feature = "cipher-aes-ofb")]
                cipher::CipherType::Aes256Ofb =>        ffi::EVP_aes_256_ofb(),

                #[cfg(feature = "cipher-aes-ctr")]
                cipher::CipherType::Aes128Ctr =>        ffi::EVP_aes_128_ctr(),
                #[cfg(feature = "cipher-aes-ctr")]
                cipher::CipherType::Aes192Ctr =>        ffi::EVP_aes_192_ctr(),
                #[cfg(feature = "cipher-aes-ctr")]
                cipher::CipherType::Aes256Ctr =>        ffi::EVP_aes_256_ctr(),

                #[cfg(feature = "cipher-bf-cfb")]
                cipher::CipherType::BfCfb =>            ffi::EVP_bf_cfb64(),

                #[cfg(feature = "cipher-camellia-cfb")]
                cipher::CipherType::Camellia128Cfb =>   ffi::EVP_camellia_128_cfb128(),
                #[cfg(feature = "cipher-camellia-cfb")]
                cipher::CipherType::Camellia192Cfb =>   ffi::EVP_camellia_192_cfb128(),
                #[cfg(feature = "cipher-camellia-cfb")]
                cipher::CipherType::Camellia256Cfb =>   ffi::EVP_camellia_256_cfb128(),

                #[cfg(feature = "cipher-cast5-cfb")]
                cipher::CipherType::Cast5Cfb =>         ffi::EVP_cast5_cfb64(),
                #[cfg(feature = "cipher-des-cfb")]
                cipher::CipherType::DesCfb =>           ffi::EVP_des_cfb64(),
                #[cfg(feature = "cipher-idea-cfb")]
                cipher::CipherType::IdeaCfb =>          ffi::EVP_idea_cfb64(),
                #[cfg(feature = "cipher-rc2-cfb")]
                cipher::CipherType::Rc2Cfb =>           ffi::EVP_rc2_cfb64(),
                #[cfg(feature = "cipher-seed-cfb")]
                cipher::CipherType::SeedCfb =>          ffi::EVP_seed_cfb128(),
                #[cfg(feature = "cipher-rc4")]
                cipher::CipherType::Rc4 =>              ffi::EVP_rc4(),

                _ => { panic!("Unsupported cipher type of OpenSSL") },
            }
        }
    }

    pub fn update(&self, data: &[u8]) -> CipherResult<Vec<u8>> {
        let pdata: *const u8 = data.as_ptr();
        let datalen: libc::c_int = data.len() as libc::c_int;

        let mut out = Vec::with_capacity(data.len() + self.cipher_type.block_size());
        unsafe { out.set_len(data.len() + self.cipher_type.block_size()); }

        let mut len: libc::c_int = 0;
        let pres: *mut u8 = out.as_mut_ptr();

        unsafe {
            if ffi::EVP_CipherUpdate(self.evp_ctx,
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
        let mut out = Vec::with_capacity(self.cipher_type.block_size());
        unsafe { out.set_len(self.cipher_type.block_size()) }

        unsafe {
            if ffi::EVP_CipherFinal(self.evp_ctx, out.as_mut_ptr(), &mut len) != 1 {
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
        let ctx = unsafe {
            let ctx = ffi::EVP_CIPHER_CTX_new();
            if ffi::EVP_CIPHER_CTX_copy(ctx, self.evp_ctx) != 1 {
                ffi::EVP_CIPHER_CTX_free(ctx);
                panic!("Failed to call EVP_CIPHER_CTX_copy");
            }
            ctx
        };

        OpenSSLCrypto {
            evp_ctx: ctx,
            cipher_type: self.cipher_type,
        }
    }
}


#[unsafe_destructor]
impl Drop for OpenSSLCrypto {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_CIPHER_CTX_cleanup(self.evp_ctx);
            ffi::EVP_CIPHER_CTX_free(self.evp_ctx);
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
/// let key = cipher::CipherType::Aes128Cfb.bytes_to_key(b"password");
/// let iv = cipher::CipherType::Aes128Cfb.gen_init_vec();
///
/// let mut enc = OpenSSLCipher::new(cipher::CipherType::Aes128Cfb, &key[0..], &iv[0..], CryptoMode::Encrypt);
/// let mut dec = OpenSSLCipher::new(cipher::CipherType::Aes128Cfb, &key[0..], &iv[0..], CryptoMode::Decrypt);
/// let message = "hello world";
/// let encrypted_message = enc.update(message.as_bytes()).unwrap();
/// let decrypted_message = dec.update(&encrypted_message[]).unwrap();
///
/// assert!(&decrypted_message[] == message.as_bytes());
/// ```
#[derive(Clone)]
pub struct OpenSSLCipher {
    worker: OpenSSLCrypto,
}

impl OpenSSLCipher {
    pub fn new(cipher_type: cipher::CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> OpenSSLCipher {
        OpenSSLCipher {
            worker: OpenSSLCrypto::new(cipher_type, &key[..], &iv[..], mode),
        }
    }
}

impl Cipher for OpenSSLCipher {
    fn update(&mut self, data: &[u8]) -> CipherResult<Vec<u8>> {
        self.worker.update(data)
    }

    fn finalize(&mut self) -> CipherResult<Vec<u8>> {
        self.worker.finalize()
    }
}

unsafe impl Send for OpenSSLCipher {}

#[cfg(test)]
mod test_openssl {
    extern crate test;
    use crypto::cipher::{self, Cipher};
    use crypto::openssl::OpenSSLCipher;
    use crypto::CryptoMode;

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
            let k = t.bytes_to_key(key.as_bytes());
            let iv = t.gen_init_vec();

            let mut enc = OpenSSLCipher::new(*t, &k[..], &iv[..], CryptoMode::Encrypt);

            let mut encrypted_msg = enc.update(message.as_bytes()).unwrap();
            encrypted_msg.push_all(&enc.finalize().unwrap()[..]);
            println!("ENC {:?}", encrypted_msg);

            let mut dec = OpenSSLCipher::new(*t, &k[..], &iv[..], CryptoMode::Decrypt);
            let mut decrypted_msg = dec.update(&encrypted_msg[..]).unwrap();
            decrypted_msg.push_all(&dec.finalize().unwrap()[..]);
            println!("DEC {:?}", &decrypted_msg[..]);

            assert_eq!(message.as_bytes(), &decrypted_msg[..]);
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
            let k = cipher::CipherType::Aes256Cfb.bytes_to_key(&key[..]);
            let v = cipher::CipherType::Aes256Cfb.gen_init_vec();

            test_data.push((msg, k, v));
        }

        b.iter(|| {
            let (ref msg, ref key, ref iv) = test_data[random::<usize>() % test_data.len()];

            let mut enc = OpenSSLCipher::new(cipher::CipherType::Aes256Cfb,
                                             &key[..], &iv[..], CryptoMode::Encrypt);
            enc.update(&msg[..]).unwrap();
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
            let k = cipher::CipherType::Aes256Cfb.bytes_to_key(&key[..]);
            let v = cipher::CipherType::Aes256Cfb.gen_init_vec();
            let mut cipher = OpenSSLCipher::new(cipher::CipherType::Aes256Cfb,
                                                &k[..], &v[..], CryptoMode::Encrypt);
            let encrypted_msg = cipher.update(&msg[..]).unwrap();
            test_data.push((k, v, encrypted_msg));
        }

        b.iter(|| {
            let (ref key, ref iv, ref encrypted_msg) = test_data[random::<usize>() % test_data.len()];
            let mut cipher = OpenSSLCipher::new(cipher::CipherType::Aes256Cfb,
                                                &key[..], &iv[..], CryptoMode::Decrypt);
            cipher.update(&encrypted_msg[..]).unwrap();
        });
        b.bytes = msg_size as u64;
    }
}
