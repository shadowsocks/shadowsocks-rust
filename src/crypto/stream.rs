//! Stream ciphers

use crypto::cipher::{CipherType, CipherCategory, CipherResult};
use crypto::openssl;
use crypto::table;
use crypto::CryptoMode;
use crypto::rc4_md5;
use crypto::dummy;
#[cfg(feature = "sodiumoxide")]
use crypto::sodium;

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

define_stream_ciphers! {
    pub TableCipher => table::TableCipher,
    pub DummyCipher => dummy::DummyCipher,
    pub Rc4Md5Cipher => rc4_md5::Rc4Md5Cipher,
    pub OpenSSLCipher => openssl::OpenSSLCipher,

    #[cfg(feature = "sodiumoxide")]
    pub SodiumCipher => sodium::SodiumCipher,
}

/// Generate a specific Cipher with key and initialize vector
pub fn new_stream(t: CipherType, key: &[u8], iv: &[u8], mode: CryptoMode) -> StreamCipherVariant {
    assert!(t.category() == CipherCategory::Stream,
            "only allow initializing with stream cipher");

    match t {
        CipherType::Table => StreamCipherVariant::new(table::TableCipher::new(key, mode)),
        CipherType::Dummy => StreamCipherVariant::new(dummy::DummyCipher),

        #[cfg(feature = "sodiumoxide")]
        CipherType::ChaCha20 |
        CipherType::Salsa20 |
        CipherType::XSalsa20 |
        CipherType::Aes128Ctr => StreamCipherVariant::new(sodium::SodiumCipher::new(t, key, iv)),

        CipherType::Rc4Md5 => StreamCipherVariant::new(rc4_md5::Rc4Md5Cipher::new(key, iv, mode)),

        _ => StreamCipherVariant::new(openssl::OpenSSLCipher::new(t, key, iv, mode)),
    }
}
