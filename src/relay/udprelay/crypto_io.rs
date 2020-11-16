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
use crate::context::Context;

use log::{debug, trace};
use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use shadowsocks_crypto::v1::{CipherCategory, CipherKind, Cipher, random_iv_or_salt};

use std::io;


/// Encrypt payload into ShadowSocks UDP encrypted packet
pub fn encrypt_payload(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &[u8],
    dst: &mut BytesMut,
) -> io::Result<()> {
    match method.category() {
        CipherCategory::None => {
            // FIXME: Is there a better way to prevent copying?
            dst.put_slice(payload);
            Ok(())
        },
        CipherCategory::Stream => {
            encrypt_payload_stream(context, method, key, payload, dst)
        },
        CipherCategory::Aead => {
            encrypt_payload_aead(context, method, key, payload, dst)
        },
    }
}

fn encrypt_payload_stream(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &[u8],
    dst: &mut BytesMut,
) -> io::Result<()> {
    let plen   = payload.len();
    let iv_len = method.iv_len();

    let mut iv = [0u8; 32];
    let iv = &mut iv[..iv_len];
    if iv_len > 0 {
        loop {
            random_iv_or_salt(iv);
            if !context.check_nonce_and_set(&iv) {
                break;
            }
        }
    } else {
        context.check_nonce_and_set(&iv);
    }


    let mut cipher = Cipher::new(method, &key, &iv);
    trace!("UDP packet generated stream iv {:?}", ByteStr::new(&iv));

    dst.reserve(iv_len + plen);

    dst.extend_from_slice(&iv);
    dst.extend_from_slice(payload);

    // Encrypted data
    let data: &mut [u8] = dst.as_mut();
    cipher.encrypt_packet(&mut data[iv_len..]);

    Ok(())
}

fn encrypt_payload_aead(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &[u8],
    dst: &mut BytesMut,
) -> io::Result<()> {
    let plen     = payload.len();
    let salt_len = method.salt_len();

    let mut salt = [0u8; 32];
    let salt = &mut salt[..salt_len];

    if salt_len > 0 {
        loop {
            random_iv_or_salt(salt);
            if !context.check_nonce_and_set(&salt) {
                break;
            }
        }
    } else {
        context.check_nonce_and_set(&salt);
    }

    let mut cipher = Cipher::new(method, &key, &salt);

    let tag_len = cipher.tag_len();

    trace!("UDP packet generated AEAD salt {:?}", ByteStr::new(&salt));

    dst.reserve(salt_len + plen + tag_len);

    // First of all, salt
    dst.extend_from_slice(&salt);
    dst.extend_from_slice(payload);
    dst.resize(dst.len() + tag_len, 0);

    // Encrypted data
    let data: &mut [u8] = dst.as_mut();
    cipher.encrypt_packet(&mut data[salt_len..]);

    Ok(())
}


/// Decrypt payload from ShadowSocks UDP encrypted packet
pub fn decrypt_payload(context: &Context, method: CipherKind, key: &[u8], payload: &[u8]) -> io::Result<Option<Vec<u8>>> {
    match method.category() {
        CipherCategory::None => {
            // FIXME: Is there a better way to prevent copying?
            let mut buf = Vec::with_capacity(payload.len());
            buf.extend_from_slice(payload);
            Ok(Some(buf))
        },
        CipherCategory::Stream => {
            decrypt_payload_stream(context, method, key, payload)
        },
        CipherCategory::Aead => {
            decrypt_payload_aead(context, method, key, payload)
        },
    }
}

fn decrypt_payload_stream(context: &Context, method: CipherKind, key: &[u8], payload: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let plen   = payload.len();
    let iv_len = method.iv_len();

    if plen < iv_len {
        return Ok(None);
    }

    let iv = &payload[..iv_len];

    if context.check_nonce_and_set(iv) {
        debug!("detected repeated iv {:?}", ByteStr::new(iv));
        return Err(io::Error::new(io::ErrorKind::Other, "detected repeated iv"));
    }

    let data = &payload[iv_len..];
    
    trace!("UDP packet got stream IV {:?}", ByteStr::new(iv));
    let mut cipher = Cipher::new(method, key, iv);

    let mut buf = vec![0u8; data.len()];
    buf[..data.len()].copy_from_slice(data);
    
    assert_eq!(cipher.decrypt_packet(&mut buf), true);
    
    Ok(Some(buf))
}

fn decrypt_payload_aead(context: &Context, method: CipherKind, key: &[u8], payload: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let salt_len = method.salt_len();
    if payload.len() < salt_len {
        return Ok(None);
    }

    let (salt, payload) = payload.split_at(salt_len);
    if context.check_nonce_and_set(salt) {
        debug!("detected repeated salt {:?}", ByteStr::new(salt));
        return Err(io::Error::new(io::ErrorKind::Other, "detected repeated salt"));
    }

    trace!("UDP packet got AEAD salt {:?}", ByteStr::new(salt));

    let mut cipher = Cipher::new(method, &key, &salt);
    let tag_len = cipher.tag_len();

    if payload.len() < tag_len {
        return Ok(None);
    }

    let mut buf = vec![0u8; payload.len()];
    buf[..payload.len()].copy_from_slice(payload);


    if !cipher.decrypt_packet(&mut buf) {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in"));
    }

    // NOTE: 移除 TAG 数据。
    buf.truncate(buf.len() - tag_len);

    Ok(Some(buf))
}
