use std::io;

use bytes::BytesMut;

/// Packet Information length in bytes
///
/// Tun device have set `IFF_NO_PI`, so ther is no prefix headers
pub const IFF_PI_PREFIX_LEN: usize = 0;

/// Prepending Packet Information
///
/// Tun device have set `IFF_NO_PI`, so there is nothing to prepend on Linux
pub fn set_packet_information(packet: &mut BytesMut) -> io::Result<()> {
    Ok(())
}
