//! Shadowsocks UDP AEAD protocol
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

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use log::trace;

use crate::{
    context::Context,
    crypto::{v1::Cipher, CipherKind},
    relay::socks5::Address,
};

/// Encrypt UDP AEAD protocol packet
pub fn encrypt_payload_aead(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let salt_len = method.salt_len();
    let addr_len = addr.serialized_len();

    // Packet = IV + ADDRESS + PAYLOAD + TAG
    dst.reserve(salt_len + addr_len + payload.len() + method.tag_len());

    // Generate IV
    dst.resize(salt_len, 0);
    let salt = &mut dst[..salt_len];

    if salt_len > 0 {
        context.generate_nonce(salt, false);
        trace!("UDP packet generated aead salt {:?}", ByteStr::new(salt));
    }

    let mut cipher = Cipher::new(method, key, salt);

    addr.write_to_buf(dst);
    dst.put_slice(payload);

    unsafe {
        dst.advance_mut(method.tag_len());
    }

    let m = &mut dst[salt_len..];
    cipher.encrypt_packet(m);
}

/// Decrypt UDP AEAD protocol packet
pub async fn decrypt_payload_aead(
    _context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    let plen = payload.len();
    let salt_len = method.salt_len();
    if plen < salt_len {
        let err = io::Error::new(ErrorKind::InvalidData, "udp packet too short for salt");
        return Err(err);
    }

    let (salt, data) = payload.split_at_mut(salt_len);
    // context.check_nonce_replay(salt)?;

    trace!("UDP packet got AEAD salt {:?}", ByteStr::new(salt));

    let mut cipher = Cipher::new(method, key, salt);
    let tag_len = cipher.tag_len();

    if data.len() < tag_len {
        return Err(io::Error::new(io::ErrorKind::Other, "udp packet too short for tag"));
    }

    if !cipher.decrypt_packet(data) {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in"));
    }

    // Truncate TAG
    let data_len = data.len() - tag_len;
    let data = &mut data[..data_len];

    let (dn, addr) = parse_packet(data).await?;

    let data_length = data_len - dn;
    let data_start_idx = salt_len + dn;
    let data_end_idx = data_start_idx + data_length;

    payload.copy_within(data_start_idx..data_end_idx, 0);

    Ok((data_length, addr))
}

async fn parse_packet(buf: &[u8]) -> io::Result<(usize, Address)> {
    let mut cur = Cursor::new(buf);
    match Address::read_from(&mut cur).await {
        Ok(address) => {
            let pos = cur.position() as usize;
            Ok((pos, address))
        }
        Err(..) => {
            let err = io::Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
            Err(err)
        }
    }
}
