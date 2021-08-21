use std::io;

use bytes::BytesMut;
use tun::platform::Device as TunDevice;

/// Packet Information length in bytes
///
/// Tun device have set `IFF_NO_PI`, so ther is no prefix headers
pub const IFF_PI_PREFIX_LEN: usize = 0;

/// Prepending Packet Information
///
/// Tun device have set `IFF_NO_PI`, so there is nothing to prepend on Linux
pub fn set_packet_information(_packet: &mut BytesMut) -> io::Result<()> {
    Ok(())
}

/// Set platform specific route configuration
pub async fn set_route_configuration(_device: &TunDevice) -> io::Result<()> {
    Ok(())
}
