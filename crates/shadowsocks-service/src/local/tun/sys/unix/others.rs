use std::{
    io::{self, Read, Write},
    marker::Unpin,
};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tun::Device;

/// Packet Information length in bytes
pub const IFF_PI_PREFIX_LEN: usize = 0;

/// Writing packet with packet information
pub async fn write_packet_with_pi<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet).await
}

/// Set platform specific route configuration
pub async fn set_route_configuration<Q>(_: &mut (dyn Device<Queue = Q> + Send)) -> io::Result<()>
where
    Q: Read + Write,
{
    Ok(())
}
