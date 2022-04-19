//! Relay server in local and server side implementations.

pub use self::socks5::Address;

pub mod socks5;
pub mod tcprelay;
pub mod udprelay;

/// AEAD 2022 maximum padding length
#[cfg(feature = "aead-cipher-2022")]
const AEAD2022_MAX_PADDING_SIZE: usize = 900;

/// Get a properly AEAD 2022 padding size according to payload's length
#[cfg(feature = "aead-cipher-2022")]
fn get_aead_2022_padding_size(payload: &[u8]) -> usize {
    use std::cell::RefCell;

    use rand::{rngs::SmallRng, Rng, SeedableRng};

    thread_local! {
        static PADDING_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
    }

    if payload.is_empty() {
        PADDING_RNG.with(|rng| rng.borrow_mut().gen::<usize>() % AEAD2022_MAX_PADDING_SIZE)
    } else {
        0
    }
}
