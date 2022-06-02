//! Network Utilities

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use tokio::io::{AsyncRead, AsyncReadExt};

/// Consumes all data from `reader` and throws away until EOF
pub async fn ignore_until_end<R>(reader: &mut R) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = [0u8; 2048];

    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
    }

    Ok(())
}

/// Helper function for converting IPv4 mapped IPv6 address
///
/// This is the same as `Ipv6Addr::to_ipv4_mapped`, but it is still unstable in the current libstd
#[allow(unused)]
pub(crate) fn to_ipv4_mapped(ipv6: &Ipv6Addr) -> Option<Ipv4Addr> {
    match ipv6.octets() {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => Some(Ipv4Addr::new(a, b, c, d)),
        _ => None,
    }
}
