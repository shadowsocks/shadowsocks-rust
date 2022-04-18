//! Crypto protocol for ShadowSocks UDP
//!
//! Payload with stream cipher
//! ```plain
//! +-------+----------+
//! |  IV   | Payload  |
//! +-------+----------+
//! | Fixed | Variable |
//! +-------+----------+
//! ```
//!
//! Payload with AEAD cipher
//!
//! ```plain
//! UDP (after encryption, *ciphertext*)
//! +--------+-----------+-----------+
//! | NONCE  |  *Data*   |  Data_TAG |
//! +--------+-----------+-----------+
//! | Fixed  | Variable  |   Fixed   |
//! +--------+-----------+-----------+
//! ```
use std::io::{self, Cursor, ErrorKind};

use bytes::{BufMut, BytesMut};

use crate::{
    context::Context,
    crypto::{CipherCategory, CipherKind},
    relay::socks5::Address,
};

#[cfg(feature = "aead-cipher-2022")]
use super::aead_2022::{
    decrypt_client_payload_aead_2022,
    decrypt_server_payload_aead_2022,
    encrypt_client_payload_aead_2022,
    encrypt_server_payload_aead_2022,
};
#[cfg(feature = "stream-cipher")]
use super::stream::{decrypt_payload_stream, encrypt_payload_stream};
use super::{
    aead::{decrypt_payload_aead, encrypt_payload_aead},
    options::UdpSocketControlData,
};

/// Encrypt `Client -> Server` payload into ShadowSocks UDP encrypted packet
pub fn encrypt_client_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    control: &UdpSocketControlData,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    match method.category() {
        CipherCategory::None => {
            dst.reserve(addr.serialized_len() + payload.len());
            addr.write_to_buf(dst);
            dst.put_slice(payload);
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => encrypt_payload_stream(context, method, key, addr, payload, dst),
        CipherCategory::Aead => encrypt_payload_aead(context, method, key, addr, payload, dst),
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => encrypt_client_payload_aead_2022(context, method, key, addr, control, payload, dst),
    }
}

/// Encrypt `Server -> Client` payload into ShadowSocks UDP encrypted packet
pub fn encrypt_server_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    control: &UdpSocketControlData,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    match method.category() {
        CipherCategory::None => {
            dst.reserve(addr.serialized_len() + payload.len());
            addr.write_to_buf(dst);
            dst.put_slice(payload);
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => encrypt_payload_stream(context, method, key, addr, payload, dst),
        CipherCategory::Aead => encrypt_payload_aead(context, method, key, addr, payload, dst),
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => encrypt_server_payload_aead_2022(context, method, key, addr, control, payload, dst),
    }
}

/// Decrypt `Client -> Server` payload from ShadowSocks UDP encrypted packet
pub async fn decrypt_client_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address, Option<UdpSocketControlData>)> {
    match method.category() {
        CipherCategory::None => {
            let mut cur = Cursor::new(payload);
            match Address::read_from(&mut cur).await {
                Ok(address) => {
                    let pos = cur.position() as usize;
                    let payload = cur.into_inner();
                    payload.copy_within(pos.., 0);
                    Ok((payload.len() - pos, address, None))
                }
                Err(..) => {
                    let err = io::Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
                    Err(err)
                }
            }
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => decrypt_payload_stream(context, method, key, payload)
            .await
            .map(|(n, a)| (n, a, None)),
        CipherCategory::Aead => decrypt_payload_aead(context, method, key, payload)
            .await
            .map(|(n, a)| (n, a, None)),
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => decrypt_client_payload_aead_2022(context, method, key, payload)
            .await
            .map(|(n, a, c)| (n, a, Some(c))),
    }
}

/// Decrypt `Server -> Client` payload from ShadowSocks UDP encrypted packet
pub async fn decrypt_server_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address, Option<UdpSocketControlData>)> {
    match method.category() {
        CipherCategory::None => {
            let mut cur = Cursor::new(payload);
            match Address::read_from(&mut cur).await {
                Ok(address) => {
                    let pos = cur.position() as usize;
                    let payload = cur.into_inner();
                    payload.copy_within(pos.., 0);
                    Ok((payload.len() - pos, address, None))
                }
                Err(..) => {
                    let err = io::Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
                    Err(err)
                }
            }
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => decrypt_payload_stream(context, method, key, payload)
            .await
            .map(|(n, a)| (n, a, None)),
        CipherCategory::Aead => decrypt_payload_aead(context, method, key, payload)
            .await
            .map(|(n, a)| (n, a, None)),
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => decrypt_server_payload_aead_2022(context, method, key, payload)
            .await
            .map(|(n, a, c)| (n, a, Some(c))),
    }
}
