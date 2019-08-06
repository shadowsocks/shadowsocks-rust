//! Stream ciphers

use std::ops::{Deref, DerefMut};

#[cfg(feature = "openssl")]
use crate::crypto::openssl;
#[cfg(feature = "rc4")]
use crate::crypto::rc4_md5;
#[cfg(feature = "sodium")]
use crate::crypto::sodium;
use crate::crypto::{
    cipher::{CipherCategory, CipherResult, CipherType},
    dummy, table, CryptoMode,
};

use bytes::BufMut;

/// Basic operation of Cipher, which is a Symmetric Cipher.
///
/// The `update` method could be called multiple times, and the `finalize` method will
/// encrypt the last block
pub trait StreamCipher {
    fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()>;
    fn finalize<B: BufMut>(&mut self, out: &mut B) -> CipherResult<()>;
    fn buffer_size(&self, data: &[u8]) -> usize;
}

macro_rules! define_stream_ciphers {
    ($( $(#[$attr:meta])* pub $name:ident => $cipher:ty, )+) => {
        /// Variant cipher which contains all possible ciphers
        pub enum StreamCipherVariant {
            $(
                $(#[$attr])*
                $name($cipher),
            )+
        }

        impl StreamCipherVariant {
            /// Creates from an actual cipher
            pub fn new<C>(cipher: C) -> StreamCipherVariant
                where StreamCipherVariant: From<C>
            {
                From::from(cipher)
            }
        }

        impl StreamCipher for StreamCipherVariant {
            fn update<B: BufMut>(&mut self, data: &[u8], out: &mut B) -> CipherResult<()> {
                match *self {
                    $(
                        $(#[$attr])*
                        StreamCipherVariant::$name(ref mut cipher) => cipher.update(data, out),
                    )+
                }
            }

            fn finalize<B: BufMut>(&mut self, out: &mut B) -> CipherResult<()> {
                match *self {
                    $(
                        $(#[$attr])*
                        StreamCipherVariant::$name(ref mut cipher) => cipher.finalize(out),
                    )+
                }
            }

            fn buffer_size(&self, data: &[u8]) -> usize {
                match *self {
                    $(
                        $(#[$attr])*
                        StreamCipherVariant::$name(ref cipher) => cipher.buffer_size(data),
                    )+
                }
            }
        }

        $(
            $(#[$attr])*
            impl From<$cipher> for StreamCipherVariant {
                fn from(cipher: $cipher) -> StreamCipherVariant {
                    StreamCipherVariant::$name(cipher)
                }
            }
        )+
    }
}

/// Variant cipher which contains all possible stream ciphers
pub struct BoxStreamCipher {
    cipher: Box<StreamCipherVariant>,
}

impl Deref for BoxStreamCipher {
    type Target = StreamCipherVariant;

    fn deref(&self) -> &StreamCipherVariant {
        &*self.cipher
    }
}

impl DerefMut for BoxStreamCipher {
    fn deref_mut(&mut self) -> &mut StreamCipherVariant {
        &mut *self.cipher
    }
}

define_stream_ciphers! {
    pub TableCipher => table::TableCipher,
    pub DummyCipher => dummy::DummyCipher,
    #[cfg(feature = "rc4")]
    pub Rc4Md5Cipher => rc4_md5::Rc4Md5Cipher,
    #[cfg(feature = "openssl")]
    pub OpenSSLCipher => openssl::OpenSSLCipher,
    #[cfg(feature = "sodium")]
    pub SodiumStreamCipher => sodium::SodiumStreamCipher,
}

/// Generate a specific Cipher with key and initialize vector
#[allow(unused_variables)]
pub fn new_stream(t: CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> BoxStreamCipher {
    assert!(
        t.category() == CipherCategory::Stream,
        "only allow initializing with stream cipher"
    );

    let cipher = match t {
        CipherType::Table => StreamCipherVariant::new(table::TableCipher::new(key, mode)),
        CipherType::Plain => StreamCipherVariant::new(dummy::DummyCipher),

        #[cfg(feature = "sodium")]
        CipherType::ChaCha20 | CipherType::Salsa20 | CipherType::XSalsa20 | CipherType::ChaCha20Ietf => {
            StreamCipherVariant::new(sodium::SodiumStreamCipher::new(t, key, iv))
        }

        #[cfg(feature = "rc4")]
        CipherType::Rc4Md5 => StreamCipherVariant::new(rc4_md5::Rc4Md5Cipher::new(key, iv, mode)),

        #[cfg(feature = "openssl")]
        CipherType::Aes128Cfb
        | CipherType::Aes128Cfb1
        | CipherType::Aes128Cfb8
        | CipherType::Aes128Cfb128
        | CipherType::Aes192Cfb
        | CipherType::Aes192Cfb1
        | CipherType::Aes192Cfb8
        | CipherType::Aes192Cfb128
        | CipherType::Aes256Cfb
        | CipherType::Aes256Cfb1
        | CipherType::Aes256Cfb8
        | CipherType::Aes256Cfb128
        | CipherType::Aes128Ctr
        | CipherType::Aes192Ctr
        | CipherType::Aes256Ctr
        | CipherType::Camellia128Cfb
        | CipherType::Camellia128Cfb1
        | CipherType::Camellia128Cfb8
        | CipherType::Camellia128Cfb128
        | CipherType::Camellia192Cfb
        | CipherType::Camellia192Cfb1
        | CipherType::Camellia192Cfb8
        | CipherType::Camellia192Cfb128
        | CipherType::Camellia256Cfb
        | CipherType::Camellia256Cfb1
        | CipherType::Camellia256Cfb8
        | CipherType::Camellia256Cfb128 => StreamCipherVariant::new(openssl::OpenSSLCipher::new(t, key, iv, mode)),

        _ => unreachable!("{} is not a stream cipher", t),
    };
    BoxStreamCipher {
        cipher: Box::new(cipher),
    }
}
