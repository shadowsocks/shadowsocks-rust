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

use std::io;

use crate::crypto::{self, CipherCategory, CipherType, CryptoMode, StreamCipher};

/// Encrypt payload into ShadowSocks UDP encrypted packet
pub fn encrypt_payload(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    match t.category() {
        CipherCategory::Stream => encrypt_payload_stream(t, key, payload),
        CipherCategory::Aead => encrypt_payload_aead(t, key, payload),
    }
}

fn encrypt_payload_stream(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let iv = t.gen_init_vec();
    let mut cipher = crypto::new_stream(t, key, &iv, CryptoMode::Encrypt);

    let mut send_payload = Vec::with_capacity(iv.len() + payload.len());
    send_payload.extend_from_slice(&iv);
    cipher.update(&payload[..], &mut send_payload)?;
    cipher.finalize(&mut send_payload)?;
    Ok(send_payload)
}

fn encrypt_payload_aead(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let salt = t.gen_salt();
    let tag_size = t.tag_size();
    let mut cipher = crypto::new_aead_encryptor(t, key, &salt);

    let mut send_payload = Vec::with_capacity(salt.len() + payload.len() + tag_size);
    send_payload.extend_from_slice(&salt);
    let start_pos = send_payload.len();
    send_payload.resize(start_pos + payload.len() + tag_size, 0);

    cipher.encrypt(payload, &mut send_payload[start_pos..]);

    Ok(send_payload)
}

/// Decrypt payload from ShadowSocks UDP encrypted packet
pub fn decrypt_payload(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    match t.category() {
        CipherCategory::Stream => decrypt_payload_stream(t, key, payload),
        CipherCategory::Aead => decrypt_payload_aead(t, key, payload),
    }
}

fn decrypt_payload_stream(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let iv_size = t.iv_size();
    if payload.len() < iv_size {
        let err = io::Error::new(io::ErrorKind::Other, "udp packet too short");
        return Err(err);
    }

    let iv = &payload[..iv_size];
    let data = &payload[iv_size..];

    let mut cipher = crypto::new_stream(t, key, iv, CryptoMode::Decrypt);

    let mut recv_payload = Vec::with_capacity(data.len());
    cipher.update(data, &mut recv_payload)?;
    cipher.finalize(&mut recv_payload)?;

    Ok(recv_payload)
}

fn decrypt_payload_aead(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let tag_size = t.tag_size();
    let salt_size = t.salt_size();

    if payload.len() < tag_size + salt_size {
        let err = io::Error::new(io::ErrorKind::Other, "udp packet too short");
        return Err(err);
    }

    let salt = &payload[..salt_size];
    let data = &payload[salt_size..];
    let data_length = payload.len() - tag_size - salt_size;

    let mut cipher = crypto::new_aead_decryptor(t, key, salt);

    let mut recv_payload = vec![0u8; data_length];
    cipher.decrypt(data, &mut recv_payload)?;

    Ok(recv_payload)
}
