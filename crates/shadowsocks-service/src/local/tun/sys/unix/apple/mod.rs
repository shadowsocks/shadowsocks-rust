use std::io::{self, ErrorKind};

use bytes::{BufMut, BytesMut};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos;
        pub use self::macos::*;
    } else {
        mod others;
        pub use self::others::*;
    }
}

/// Packet Information length in bytes
pub const IFF_PI_PREFIX_LEN: usize = 4;

/// Prepending Packet Information
///
/// ```
/// +--------+--------+--------+--------+
/// | Flags (0)       | Protocol        |
/// +--------+--------+--------+--------+
/// ```
pub fn set_packet_information(packet: &mut BytesMut) -> io::Result<()> {
    if packet.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "empty packet"));
    }

    // FIXME: Bad Performance because of new allocation and memory copies.
    let mut full_packet = BytesMut::with_capacity(4 + packet.len());

    // Flags, always 0
    full_packet.put_u16(0);
    // Protocol, infer from the original packet
    let protocol = match packet[0] >> 4 {
        4 => libc::PF_INET,
        6 => libc::PF_INET6,
        _ => return Err(io::Error::new(ErrorKind::InvalidData, "neither an IPv4 or IPv6 packet")),
    };
    full_packet.put_u16(protocol as u16);

    // Append the whole packet
    full_packet.put_slice(&packet);

    *packet = full_packet;
    Ok(())
}
