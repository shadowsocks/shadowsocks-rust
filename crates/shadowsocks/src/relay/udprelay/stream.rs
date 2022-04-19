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

use std::io::{self, Cursor, ErrorKind};

use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use log::trace;

use crate::{
    context::Context,
    crypto::{v1::Cipher, CipherKind},
    relay::socks5::Address,
};

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
pub async fn decrypt_payload_stream(
    _context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    let plen = payload.len();
    let iv_len = method.iv_len();

    if plen < iv_len {
        let err = io::Error::new(ErrorKind::InvalidData, "udp packet too short for iv");
        return Err(err);
    }

    let (iv, data) = payload.split_at_mut(iv_len);
    // context.check_nonce_replay(iv)?;

    trace!("UDP packet got stream IV {:?}", ByteStr::new(iv));
    let mut cipher = Cipher::new(method, key, iv);

    assert!(cipher.decrypt_packet(data));

    let (dn, addr) = parse_packet(data).await?;

    let data_start_idx = iv_len + dn;
    let data_length = payload.len() - data_start_idx;
    payload.copy_within(data_start_idx.., 0);

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
