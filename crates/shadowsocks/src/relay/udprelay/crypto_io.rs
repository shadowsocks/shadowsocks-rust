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
use std::io::Cursor;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    config::ServerUserManager,
    context::Context,
    crypto::{CipherCategory, CipherKind},
    relay::socks5::{Address, Error as Socks5Error},
};

#[cfg(feature = "aead-cipher")]
use super::aead::{decrypt_payload_aead, encrypt_payload_aead};
#[cfg(feature = "aead-cipher-2022")]
use super::aead_2022::{
    decrypt_client_payload_aead_2022, decrypt_server_payload_aead_2022, encrypt_client_payload_aead_2022,
    encrypt_server_payload_aead_2022,
};
use super::options::UdpSocketControlData;
#[cfg(feature = "stream-cipher")]
use super::stream::{decrypt_payload_stream, encrypt_payload_stream};

/// UDP shadowsocks protocol errors
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("invalid address in packet, {0}")]
    InvalidAddress(Socks5Error),
    #[cfg(feature = "stream-cipher")]
    #[error(transparent)]
    StreamError(#[from] super::stream::ProtocolError),
    #[cfg(feature = "aead-cipher")]
    #[error(transparent)]
    AeadError(#[from] super::aead::ProtocolError),
    #[cfg(feature = "aead-cipher-2022")]
    #[error(transparent)]
    Aead2022Error(#[from] super::aead_2022::ProtocolError),
}

/// UDP shadowsocks protocol errors
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Encrypt `Client -> Server` payload into ShadowSocks UDP encrypted packet
#[allow(clippy::too_many_arguments)]
pub fn encrypt_client_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    control: &UdpSocketControlData,
    identity_keys: &[Bytes],
    payload: &[u8],
    dst: &mut BytesMut,
) {
    match method.category() {
        CipherCategory::None => {
            let _ = context;
            let _ = key;
            let _ = control;
            let _ = identity_keys;
            dst.reserve(addr.serialized_len() + payload.len());
            addr.write_to_buf(dst);
            dst.put_slice(payload);
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => {
            let _ = control;
            let _ = identity_keys;
            encrypt_payload_stream(context, method, key, addr, payload, dst)
        }
        #[cfg(feature = "aead-cipher")]
        CipherCategory::Aead => {
            let _ = control;
            let _ = identity_keys;
            encrypt_payload_aead(context, method, key, addr, payload, dst)
        }
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => {
            encrypt_client_payload_aead_2022(context, method, key, addr, control, identity_keys, payload, dst)
        }
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
            let _ = context;
            let _ = key;
            let _ = control;
            dst.reserve(addr.serialized_len() + payload.len());
            addr.write_to_buf(dst);
            dst.put_slice(payload);
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => {
            let _ = control;
            encrypt_payload_stream(context, method, key, addr, payload, dst)
        }
        #[cfg(feature = "aead-cipher")]
        CipherCategory::Aead => {
            let _ = control;
            encrypt_payload_aead(context, method, key, addr, payload, dst)
        }
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => encrypt_server_payload_aead_2022(context, method, key, addr, control, payload, dst),
    }
}

/// Decrypt `Client -> Server` payload from ShadowSocks UDP encrypted packet
pub fn decrypt_client_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
    user_manager: Option<&ServerUserManager>,
) -> ProtocolResult<(usize, Address, Option<UdpSocketControlData>)> {
    match method.category() {
        CipherCategory::None => {
            let _ = context;
            let _ = key;
            let _ = user_manager;
            let mut cur = Cursor::new(payload);
            match Address::read_cursor(&mut cur) {
                Ok(address) => {
                    let pos = cur.position() as usize;
                    let payload = cur.into_inner();
                    payload.copy_within(pos.., 0);
                    Ok((payload.len() - pos, address, None))
                }
                Err(err) => Err(ProtocolError::InvalidAddress(err)),
            }
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => {
            let _ = user_manager;
            decrypt_payload_stream(context, method, key, payload)
                .map(|(n, a)| (n, a, None))
                .map_err(Into::into)
        }
        #[cfg(feature = "aead-cipher")]
        CipherCategory::Aead => {
            let _ = user_manager;
            decrypt_payload_aead(context, method, key, payload)
                .map(|(n, a)| (n, a, None))
                .map_err(Into::into)
        }
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => decrypt_client_payload_aead_2022(context, method, key, payload, user_manager)
            .map(|(n, a, c)| (n, a, Some(c)))
            .map_err(Into::into),
    }
}

/// Decrypt `Server -> Client` payload from ShadowSocks UDP encrypted packet
pub fn decrypt_server_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> ProtocolResult<(usize, Address, Option<UdpSocketControlData>)> {
    match method.category() {
        CipherCategory::None => {
            let _ = context;
            let _ = key;

            let mut cur = Cursor::new(payload);
            match Address::read_cursor(&mut cur) {
                Ok(address) => {
                    let pos = cur.position() as usize;
                    let payload = cur.into_inner();
                    payload.copy_within(pos.., 0);
                    Ok((payload.len() - pos, address, None))
                }
                Err(err) => Err(ProtocolError::InvalidAddress(err)),
            }
        }
        #[cfg(feature = "stream-cipher")]
        CipherCategory::Stream => decrypt_payload_stream(context, method, key, payload)
            .map(|(n, a)| (n, a, None))
            .map_err(Into::into),
        #[cfg(feature = "aead-cipher")]
        CipherCategory::Aead => decrypt_payload_aead(context, method, key, payload)
            .map(|(n, a)| (n, a, None))
            .map_err(Into::into),
        #[cfg(feature = "aead-cipher-2022")]
        CipherCategory::Aead2022 => decrypt_server_payload_aead_2022(context, method, key, payload)
            .map(|(n, a, c)| (n, a, Some(c)))
            .map_err(Into::into),
    }
}
