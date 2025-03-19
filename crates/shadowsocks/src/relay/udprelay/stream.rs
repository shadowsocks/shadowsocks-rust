//! Shadowsocks UDP Stream Protocol
//!
//! Payload with stream cipher
//! ```plain
//! +-------+----------+
//! |  IV   | Payload  |
//! +-------+----------+
//! | Fixed | Variable |
//! +-------+----------+
//! ```

use std::io::Cursor;

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use log::trace;

use crate::{
    context::Context,
    crypto::{CipherKind, v1::Cipher},
    relay::socks5::{Address, Error as Socks5Error},
};

/// Stream protocol error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("packet too short, at least {0} bytes, but only {1} bytes")]
    PacketTooShort(usize, usize),
    #[error("invalid address in packet, {0}")]
    InvalidAddress(Socks5Error),
}

/// Stream protocol result
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Encrypt UDP stream protocol packet
pub fn encrypt_payload_stream(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let iv_len = method.iv_len();
    let addr_len = addr.serialized_len();

    // Packet = IV + ADDRESS + PAYLOAD
    dst.reserve(iv_len + addr_len + payload.len());

    // Generate IV
    dst.resize(iv_len, 0);
    let iv = &mut dst[..iv_len];

    if iv_len > 0 {
        context.generate_nonce(method, iv, false);
        trace!("UDP packet generated stream iv {:?}", ByteStr::new(iv));
    }

    let mut cipher = Cipher::new(method, key, iv);

    addr.write_to_buf(dst);
    dst.put_slice(payload);
    let m = &mut dst[iv_len..];
    cipher.encrypt_packet(m);
}

/// Decrypt UDP stream protocol packet
pub fn decrypt_payload_stream(
    _context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> ProtocolResult<(usize, Address)> {
    let plen = payload.len();
    let iv_len = method.iv_len();

    if plen < iv_len {
        return Err(ProtocolError::PacketTooShort(iv_len, plen));
    }

    let (iv, data) = payload.split_at_mut(iv_len);
    // context.check_nonce_replay(iv)?;

    trace!("UDP packet got stream IV {:?}", ByteStr::new(iv));
    let mut cipher = Cipher::new(method, key, iv);

    assert!(cipher.decrypt_packet(data));

    let (dn, addr) = parse_packet(data)?;

    let data_start_idx = iv_len + dn;
    let data_length = payload.len() - data_start_idx;
    payload.copy_within(data_start_idx.., 0);

    Ok((data_length, addr))
}

#[inline]
fn parse_packet(buf: &[u8]) -> ProtocolResult<(usize, Address)> {
    let mut cur = Cursor::new(buf);
    match Address::read_cursor(&mut cur) {
        Ok(address) => {
            let pos = cur.position() as usize;
            Ok((pos, address))
        }
        Err(err) => Err(ProtocolError::InvalidAddress(err)),
    }
}
