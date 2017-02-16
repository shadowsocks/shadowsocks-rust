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

use crypto::{self, CipherType, CipherCategory, CryptoMode};
use crypto::StreamCipher;

/// Encrypt payload into ShadowSocks UDP encrypted packet
pub fn encrypt_payload(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    match t.category() {
        CipherCategory::Stream => encrypt_payload_stream(t, key, payload),
        CipherCategory::Aead => encrypt_payload_aead(t, key, payload),
    }
}

fn encrypt_payload_stream(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut iv = t.gen_init_vec();
    let mut cipher = crypto::new_stream(t, key, &iv, CryptoMode::Encrypt);

    let mut send_payload = Vec::with_capacity(iv.len() + payload.len());
    send_payload.append(&mut iv);
    try!(cipher.update(&payload[..], &mut send_payload));
    try!(cipher.finalize(&mut send_payload));
    Ok(send_payload)
}

fn encrypt_payload_aead(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut iv = t.gen_init_vec();
    let tag_size = t.tag_size();
    let mut cipher = crypto::new_aead_encryptor(t, key, &iv);

    let mut send_payload = Vec::with_capacity(iv.len() + payload.len() + tag_size);
    send_payload.append(&mut iv);
    let start_pos = send_payload.len();
    send_payload.resize(start_pos + payload.len(), 0);

    let mut tag_buf = vec![0u8; tag_size];

    cipher.encrypt(payload, &mut send_payload[start_pos..], &mut tag_buf);

    send_payload.append(&mut tag_buf);

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
    try!(cipher.update(data, &mut recv_payload));
    try!(cipher.finalize(&mut recv_payload));

    Ok(recv_payload)
}

fn decrypt_payload_aead(t: CipherType, key: &[u8], payload: &[u8]) -> io::Result<Vec<u8>> {
    let tag_size = t.tag_size();
    let iv_size = t.iv_size();

    if payload.len() < tag_size + iv_size {
        let err = io::Error::new(io::ErrorKind::Other, "udp packet too short");
        return Err(err);
    }

    let nounce = &payload[..iv_size];
    let data = &payload[iv_size..payload.len() - tag_size];
    let tag = &payload[payload.len() - tag_size..];
    let data_length = payload.len() - tag_size - iv_size;

    let mut cipher = crypto::new_aead_decryptor(t, key, nounce);

    let mut recv_payload = vec![0u8; data_length];
    try!(cipher.decrypt(data, &mut recv_payload, tag));

    Ok(recv_payload)
}