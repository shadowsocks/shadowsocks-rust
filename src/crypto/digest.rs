//! Message digest algorithm

use md5::Md5;
use ring::digest::{Context, SHA1, SHA1_OUTPUT_LEN};

use bytes::BufMut;

/// Digest trait
pub trait Digest: Send {
    /// Update data
    fn update(&mut self, data: &[u8]);

    /// Generates digest
    fn digest<B: BufMut>(&mut self, buf: &mut B);

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
        DigestType::Md5 => DigestVariant::Md5(Md5::default()),
        DigestType::Sha1 | DigestType::Sha => DigestVariant::Sha1(Context::new(&SHA1)),
    }
}

/// Variant of supported digest
pub enum DigestVariant {
    Md5(Md5),
    Sha1(Context),
}

impl Digest for DigestVariant {
    fn update(&mut self, data: &[u8]) {
        use md5::Digest;

        match *self {
            DigestVariant::Md5(ref mut d) => d.input(data),
            DigestVariant::Sha1(ref mut d) => d.update(data),
        }
    }

    fn digest<B: BufMut>(&mut self, buf: &mut B) {
        use md5::Digest;

        match *self {
            DigestVariant::Md5(ref d) => buf.put(&*d.clone().result()),
            DigestVariant::Sha1(ref d) => buf.put(d.clone().finish().as_ref()),
        }
    }

    fn digest_len(&self) -> usize {
        use typenum::Unsigned;
        use md5::Digest;

        match *self {
            DigestVariant::Md5(_) => <Md5 as Digest>::OutputSize::to_usize(),
            DigestVariant::Sha1(_) => SHA1_OUTPUT_LEN,
        }
    }

    fn reset(&mut self) {
        match *self {
            DigestVariant::Md5(ref mut d) => d.clone_from(&Md5::default()),
            DigestVariant::Sha1(ref mut d) => d.clone_from(&Context::new(&SHA1)),
        }
    }
}
