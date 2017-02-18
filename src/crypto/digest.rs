//! Message digest algorithm

use rust_crypto::md5::Md5;
use rust_crypto::sha1::Sha1;

/// Digest trait
pub trait Digest: Send {
    /// Update data
    fn update(&mut self, data: &[u8]);

    /// Generates digest
    fn digest(&mut self, buf: &mut Vec<u8>);

    /// Length of digest
    fn digest_len(&self) -> usize;

    /// Reset digest
    fn reset(&mut self);
}

/// Type of defined digests
#[derive(Clone, Copy)]
pub enum DigestType {
    Md5,
    Sha1,
    Sha,
}

/// Create digest with type
pub fn with_type(t: DigestType) -> DigestVariant {
    match t {
        DigestType::Md5 => DigestVariant::Md5(Md5::new()),
        DigestType::Sha1 | DigestType::Sha => DigestVariant::Sha1(Sha1::new()),
    }
}

/// Variant of supported digest
pub enum DigestVariant {
    Md5(Md5),
    Sha1(Sha1),
}

impl Digest for DigestVariant {
    fn update(&mut self, data: &[u8]) {
        use rust_crypto::digest::Digest;

        match *self {
            DigestVariant::Md5(ref mut d) => d.input(data),
            DigestVariant::Sha1(ref mut d) => d.input(data),
        }
    }

    fn digest(&mut self, buf: &mut Vec<u8>) {
        use rust_crypto::digest::Digest;

        let output_bytes = match *self {
            DigestVariant::Md5(ref d) => d.output_bytes(),
            DigestVariant::Sha1(ref d) => d.output_bytes(),
        };

        let orig_len = buf.len();
        buf.resize(orig_len + output_bytes, 0);
        match *self {
            DigestVariant::Md5(ref mut d) => d.result(&mut buf[orig_len..]),
            DigestVariant::Sha1(ref mut d) => d.result(&mut buf[orig_len..]),
        }
    }

    fn digest_len(&self) -> usize {
        use rust_crypto::digest::Digest;

        match *self {
            DigestVariant::Md5(ref d) => d.output_bytes(),
            DigestVariant::Sha1(ref d) => d.output_bytes(),
        }
    }

    fn reset(&mut self) {
        use rust_crypto::digest::Digest;

        match *self {
            DigestVariant::Md5(ref mut d) => d.reset(),
            DigestVariant::Sha1(ref mut d) => d.reset(),
        }
    }
}