//! Shadowsocks UDP AEAD 2022 protocol
//!
//! Payload with AEAD 2022 cipher
//!
//! Client -> Server
//!
//! ```plain
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Client Session ID                                             |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Packet ID                                                     |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | TYPE  |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | UNIX Epoch Timestamp                                          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | PADDING SIZE  | Padding (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Address (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Payload (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```
//!
//! Server -> Client
//!
//! ```plain
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Server Session ID                                             |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Packet ID                                                     |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | TYPE  |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | UNIX Epoch Timestamp                                          |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Client Session ID                                             |
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | PADDING SIZE  | Padding (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Address (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! | Payload (Variable ...)
//! +-------+-------+-------+-------+-------+-------+-------+-------+
//! ```

use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io::{self, Cursor, ErrorKind, Seek, SeekFrom},
    rc::Rc,
    slice,
    time::{Duration, SystemTime},
};

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
    Aes256,
    Block,
};
use byte_string::ByteStr;
use bytes::{Buf, BufMut, BytesMut};
use log::{error, trace};
use lru_time_cache::LruCache;
use rand::{rngs::SmallRng, Rng, SeedableRng};

use crate::{
    context::Context,
    crypto::{
        v2::udp::{ChaCha20Poly1305Cipher, UdpCipher},
        CipherKind,
    },
    relay::socks5::Address,
};

use super::options::UdpSocketControlData;

const CLIENT_SOCKET_TYPE: u8 = 0;
const SERVER_SOCKET_TYPE: u8 = 1;
const MAX_PADDING_SIZE: usize = 900;
const SERVER_PACKET_TIMESTAMP_MAX_DIFF: u64 = 30;

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct CipherKey {
    method: CipherKind,
    key: usize,
    session_id: u64,
}

impl PartialOrd for CipherKey {
    fn partial_cmp(&self, other: &CipherKey) -> Option<Ordering> {
        let hash1 = {
            let mut hasher = DefaultHasher::new();
            self.hash(&mut hasher);
            hasher.finish()
        };
        let hash2 = {
            let mut hasher = DefaultHasher::new();
            other.hash(&mut hasher);
            hasher.finish()
        };

        hash1.partial_cmp(&hash2)
    }
}

impl Ord for CipherKey {
    fn cmp(&self, other: &CipherKey) -> Ordering {
        let hash1 = {
            let mut hasher = DefaultHasher::new();
            self.hash(&mut hasher);
            hasher.finish()
        };
        let hash2 = {
            let mut hasher = DefaultHasher::new();
            other.hash(&mut hasher);
            hasher.finish()
        };

        hash1.cmp(&hash2)
    }
}

thread_local! {
    static PADDING_RNG: RefCell<SmallRng> = RefCell::new(SmallRng::from_entropy());
    static CIPHER_CACHE: RefCell<LruCache<CipherKey, Rc<UdpCipher>>> =
        RefCell::new(LruCache::with_expiry_duration_and_capacity(Duration::from_secs(60), 102400));
}

#[inline]
fn get_padding_size(payload: &[u8]) -> usize {
    if payload.is_empty() {
        PADDING_RNG.with(|rng| rng.borrow_mut().gen::<usize>() % MAX_PADDING_SIZE)
    } else {
        0
    }
}

#[inline]
pub fn get_now_timestamp() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime::now() is before UNIX Epoch!"),
    }
}

fn get_cipher(method: CipherKind, key: &[u8], session_id: u64) -> Rc<UdpCipher> {
    CIPHER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();

        let cache_key = CipherKey {
            method,
            // The key is stored in ServerConfig structure, so the address of it won't change.
            key: key.as_ptr() as usize,
            session_id,
        };

        cache
            .entry(cache_key)
            .or_insert_with(|| Rc::new(UdpCipher::new(method, key, session_id)))
            .clone()
    })
}

fn encrypt_message(_context: &Context, method: CipherKind, key: &[u8], packet: &mut BytesMut, session_id: u64) {
    unsafe {
        packet.advance_mut(method.tag_len());
    }

    match method {
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
            // ChaCha20-Poly1305 uses PSK as key, prepended nonce in packet
            let nonce_size = ChaCha20Poly1305Cipher::nonce_size();

            let cipher = get_cipher(method, key, session_id);

            let (nonce, message) = packet.split_at_mut(nonce_size);
            cipher.encrypt_packet(nonce, message);
        }
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            // AES-*-GCM uses derived key, and part of the packet header as nonce

            let cipher = get_cipher(method, key, session_id);

            // Encrypt the rest of the packet with AEAD cipher (AES-*-GCM)
            let (packet_header, message) = packet.split_at_mut(16);
            let nonce = &packet_header[4..16];
            cipher.encrypt_packet(nonce, message);

            // [SessionID + PacketID] is encrypted with AES-ECB with PSK
            // No padding is required because these 2 fields are 128-bits, which is exactly the same as AES's block size
            match method {
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                    let cipher = Aes128::new_from_slice(key).expect("AES-128 init");
                    let block = Block::from_mut_slice(&mut packet[0..16]);
                    cipher.encrypt_block(block);
                }
                CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                    let cipher = Aes256::new_from_slice(key).expect("AES-256 init");
                    let block = Block::from_mut_slice(&mut packet[0..16]);
                    cipher.encrypt_block(block);
                }
                _ => unreachable!("{} is not an AES-*-GCM cipher", method),
            }
        }
        _ => unreachable!("{} is not an AEAD 2022 cipher", method),
    }
}

fn decrypt_message(context: &Context, method: CipherKind, key: &[u8], packet: &mut [u8]) -> bool {
    match method {
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
            // ChaCha20-Poly1305 uses PSK as key, prepended nonce in packet
            let nonce_size = ChaCha20Poly1305Cipher::nonce_size();

            let (nonce, message) = packet.split_at_mut(nonce_size);
            if let Err(..) = context.check_nonce_replay(nonce) {
                error!("detected replayed nonce: {:?}", ByteStr::new(nonce));
                return false;
            }

            // NOTE: ChaCha20-Poly1305's session_id is not required because it uses PSK directly
            //
            // But still, we get the session_id for cache
            let session_id = {
                let session_id_buf = &message[0..8];
                let session_id_slice: &[u64] = unsafe { slice::from_raw_parts(session_id_buf.as_ptr() as *const _, 1) };
                u64::from_be(session_id_slice[0])
            };

            let cipher = get_cipher(method, key, session_id);

            if !cipher.decrypt_packet(nonce, message) {
                return false;
            }
        }
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            // AES-*-GCM uses derived key, and part of the packet header as nonce
            //
            // Decrypt the header block first
            // [SessionID + PacketID] is encrypted with AES-ECB with PSK
            // No padding is required because these 2 fields are 128-bits, which is exactly the same as AES's block size

            let (packet_header, message) = packet.split_at_mut(16);

            match method {
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
                    let cipher = Aes128::new_from_slice(key).expect("AES-128 init");
                    let block = Block::from_mut_slice(packet_header);
                    cipher.decrypt_block(block);
                }
                CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                    let cipher = Aes256::new_from_slice(key).expect("AES-256 init");
                    let block = Block::from_mut_slice(packet_header);
                    cipher.decrypt_block(block);
                }
                _ => unreachable!("{} is not an AES-*-GCM cipher", method),
            }

            // Session ID is the first 64-bits

            let session_id = {
                let session_id_buf = &packet_header[0..8];
                let session_id_slice: &[u64] = unsafe { slice::from_raw_parts(session_id_buf.as_ptr() as *const _, 1) };
                u64::from_be(session_id_slice[0])
            };

            let nonce = &packet_header[4..16];

            let cipher = {
                if let Err(..) = context.check_nonce_replay(nonce) {
                    error!("detected replayed nonce: {:?}", ByteStr::new(nonce));
                    return false;
                }

                get_cipher(method, key, session_id)
            };

            if !cipher.decrypt_packet(nonce, message) {
                return false;
            }
        }
        _ => unreachable!("{} is not an AEAD 2022 cipher", method),
    }

    true
}

#[inline]
fn get_nonce_len(method: CipherKind) -> usize {
    match method {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => 0,
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => method.nonce_len(),
        _ => unreachable!("{} is not an AEAD 2022 cipher", method),
    }
}

/// Encrypt `Client -> Server` UDP AEAD protocol packet
pub fn encrypt_client_payload_aead_2022(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    control: &UdpSocketControlData,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let padding_size = get_padding_size(payload);
    let nonce_size = get_nonce_len(method);

    dst.reserve(
        nonce_size + 8 + 8 + 1 + 8 + 2 + padding_size + addr.serialized_len() + payload.len() + method.tag_len(),
    );

    // Generate IV
    if nonce_size > 0 {
        unsafe {
            dst.advance_mut(nonce_size);
        }
        let nonce = &mut dst[..nonce_size];

        context.generate_nonce(nonce, false);
        trace!("UDP packet generated aead nonce {:?}", ByteStr::new(nonce));
    }

    // Add header fields
    dst.put_u64(control.client_session_id);
    dst.put_u64(control.packet_id);
    dst.put_u8(CLIENT_SOCKET_TYPE);
    dst.put_u64(get_now_timestamp());
    dst.put_u16(padding_size as u16);
    if padding_size > 0 {
        unsafe {
            dst.advance_mut(padding_size);
        }
    }
    addr.write_to_buf(dst);
    dst.put_slice(payload);

    encrypt_message(context, method, key, dst, control.client_session_id);
}

/// Decrypt `Client -> Server` UDP AEAD protocol packet
pub async fn decrypt_client_payload_aead_2022(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address, UdpSocketControlData)> {
    let nonce_len = get_nonce_len(method);
    let tag_len = method.tag_len();
    if payload.len() < nonce_len + tag_len + 8 + 8 + 1 + 8 + 2 {
        let err = io::Error::new(ErrorKind::InvalidData, "udp packet too short");
        return Err(err);
    }

    if !decrypt_message(context, method, key, payload) {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in"));
    }

    let data = &payload[nonce_len..payload.len() - tag_len];
    let mut cursor = Cursor::new(data);

    let client_session_id = cursor.get_u64();
    let packet_id = cursor.get_u64();
    let socket_type = cursor.get_u8();
    if socket_type != CLIENT_SOCKET_TYPE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("invalid socket type {}", socket_type),
        ));
    }
    let timestamp = cursor.get_u64();

    let now = get_now_timestamp();
    if now.abs_diff(timestamp) > SERVER_PACKET_TIMESTAMP_MAX_DIFF {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("received TCP response header with aged timestamp: {}", timestamp),
        ));
    }

    let padding_size = cursor.get_u16() as usize;
    if padding_size > 0 {
        cursor.seek(SeekFrom::Current(padding_size as i64))?;
    }

    let control = UdpSocketControlData {
        client_session_id,
        server_session_id: 0,
        packet_id,
    };

    let addr = Address::read_from(&mut cursor).await?;

    let payload_start = cursor.position() as usize;
    let payload_len = data.len() - payload_start;

    payload.copy_within(nonce_len + payload_start..nonce_len + payload_start + payload_len, 0);

    Ok((payload_len, addr, control))
}

/// Encrypt `Server -> Client` UDP AEAD protocol packet
pub fn encrypt_server_payload_aead_2022(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    control: &UdpSocketControlData,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let padding_size = get_padding_size(payload);
    let nonce_size = get_nonce_len(method);

    dst.reserve(
        nonce_size + 8 + 8 + 1 + 8 + 8 + 2 + padding_size + addr.serialized_len() + payload.len() + method.tag_len(),
    );

    // Generate IV
    if nonce_size > 0 {
        unsafe {
            dst.advance_mut(nonce_size);
        }
        let nonce = &mut dst[..nonce_size];

        context.generate_nonce(nonce, false);
        trace!("UDP packet generated aead nonce {:?}", ByteStr::new(nonce));
    }

    // Add header fields
    dst.put_u64(control.server_session_id);
    dst.put_u64(control.packet_id);
    dst.put_u8(SERVER_SOCKET_TYPE);
    dst.put_u64(get_now_timestamp());
    dst.put_u64(control.client_session_id);
    dst.put_u16(padding_size as u16);
    if padding_size > 0 {
        unsafe {
            dst.advance_mut(padding_size);
        }
    }
    addr.write_to_buf(dst);
    dst.put_slice(payload);

    encrypt_message(context, method, key, dst, control.server_session_id);
}

/// Decrypt `Server -> Client` UDP AEAD protocol packet
pub async fn decrypt_server_payload_aead_2022(
    context: &Context,
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address, UdpSocketControlData)> {
    let nonce_len = get_nonce_len(method);
    let tag_len = method.tag_len();
    if payload.len() < nonce_len + tag_len + 8 + 8 + 1 + 8 + 2 {
        let err = io::Error::new(ErrorKind::InvalidData, "udp packet too short");
        return Err(err);
    }

    if !decrypt_message(context, method, key, payload) {
        return Err(io::Error::new(io::ErrorKind::Other, "invalid tag-in"));
    }

    let data = &payload[nonce_len..payload.len() - tag_len];
    let mut cursor = Cursor::new(data);

    let server_session_id = cursor.get_u64();
    let packet_id = cursor.get_u64();
    let socket_type = cursor.get_u8();
    if socket_type != SERVER_SOCKET_TYPE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("invalid socket type {}", socket_type),
        ));
    }
    let timestamp = cursor.get_u64();

    let now = get_now_timestamp();
    if now.abs_diff(timestamp) > SERVER_PACKET_TIMESTAMP_MAX_DIFF {
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("received TCP response header with aged timestamp: {}", timestamp),
        ));
    }

    let client_session_id = cursor.get_u64();

    let padding_size = cursor.get_u16() as usize;
    if padding_size > 0 {
        cursor.seek(SeekFrom::Current(padding_size as i64))?;
    }

    let control = UdpSocketControlData {
        client_session_id,
        server_session_id,
        packet_id,
    };

    let addr = Address::read_from(&mut cursor).await?;

    let payload_start = cursor.position() as usize;
    let payload_len = data.len() - payload_start;

    payload.copy_within(nonce_len + payload_start..nonce_len + payload_start + payload_len, 0);

    Ok((payload_len, addr, control))
}
