use std::{io, marker::Unpin};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tun::{platform::Device as TunDevice, Device};

/// Packet Information length in bytes
///
/// Tun device on Windows (https://wintun.net) doesn't have Packet Information header, so there is no prefix headers
pub const IFF_PI_PREFIX_LEN: usize = 0;

/// Writing packet with packet information
///
/// Tun device on Windows (https://wintun.net) doesn't have Packet Information header, so there is nothing to prepend on Windows
pub async fn write_packet_with_pi<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet).await
}

/// Set platform specific route configuration
pub async fn set_route_configuration(_device: &mut TunDevice) -> io::Result<()> {
    Ok(())
}
