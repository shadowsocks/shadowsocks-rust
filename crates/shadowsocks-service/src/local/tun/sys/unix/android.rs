use std::io::{self, ErrorKind};

use bytes::{BufMut, BytesMut};
use tun::platform::Device as TunDevice;

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
        4 => libc::ETH_P_IP,
        6 => libc::ETH_P_IPV6,
        _ => return Err(io::Error::new(ErrorKind::InvalidData, "neither an IPv4 or IPv6 packet")),
    };
    full_packet.put_u16(protocol as u16);

    // Append the whole packet
    full_packet.put_slice(packet);

    *packet = full_packet;
    Ok(())
}

/// Set platform specific route configuration
pub async fn set_route_configuration(_device: &TunDevice) -> io::Result<()> {
    Ok(())
}
