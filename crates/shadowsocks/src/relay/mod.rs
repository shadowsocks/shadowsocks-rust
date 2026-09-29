//! Relay server in local and server side implementations.

pub use self::socks5::Address;

pub mod socks5;
pub mod tcprelay;
pub mod udprelay;

/// AEAD 2022 maximum padding length
#[cfg(feature = "aead-cipher-2022")]
const AEAD2022_MAX_PADDING_SIZE: usize = 900;

/// Get a properly AEAD 2022 padding size according to payload's length
///
/// SIP022: In a request header, either initial payload or padding MUST be present.
/// When making a request header, if payload is not available, add non-zero random length padding.
/// https://shadowsocks.org/doc/sip022.html
#[cfg(feature = "aead-cipher-2022")]
fn get_aead_2022_padding_size(payload: &[u8]) -> usize {
    use std::cell::RefCell;

    use rand::{RngExt, rngs::SmallRng};

    thread_local! {
        static PADDING_RNG: RefCell<SmallRng> = RefCell::new(rand::make_rng());
    }

    if payload.is_empty() {
        // A padding size of 0 with an empty payload would be rejected by servers
        // (and is a violation of the AEAD-2022 spec), so the range starts from 1.
        PADDING_RNG.with(|rng| rng.borrow_mut().random_range::<usize, _>(1..=AEAD2022_MAX_PADDING_SIZE))
    } else {
        0
    }
}

#[cfg(feature = "aead-cipher-2022")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_aead_2022_padding_size() {
        // Non-empty payload needs no padding
        assert_eq!(get_aead_2022_padding_size(b"payload"), 0);

        // Empty payload MUST take a non-zero random padding size
        // https://github.com/shadowsocks/shadowsocks-rust/issues/2184
        for _ in 0..10000 {
            let padding_size = get_aead_2022_padding_size(b"");
            assert!(
                (1..=AEAD2022_MAX_PADDING_SIZE).contains(&padding_size),
                "padding size {padding_size} should be within 1..={AEAD2022_MAX_PADDING_SIZE}"
            );
        }
    }
}
