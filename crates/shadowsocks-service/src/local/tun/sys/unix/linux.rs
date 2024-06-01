use std::{
    io::{self, Read, Write},
    marker::Unpin,
};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tun2::AbstractDevice;

/// Packet Information length in bytes
///
/// Tun device have set `IFF_NO_PI`, so ther is no prefix headers
pub const IFF_PI_PREFIX_LEN: usize = 0;

/// Writing packet with packet information
///
/// Tun device have set `IFF_NO_PI`, so there is nothing to prepend on Linux
pub async fn write_packet_with_pi<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet).await
}

/// Set platform specific route configuration
pub async fn set_route_configuration<D>(device: &mut D) -> io::Result<()>
where
    D: AbstractDevice,
{
    Ok(())
}
