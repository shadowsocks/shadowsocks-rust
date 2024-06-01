use std::io::{self, Read, Write};

use tun2::AbstractDevice;

/// Set platform specific route configuration
pub async fn set_route_configuration<D>(device: &mut D) -> io::Result<()>
where
    D: AbstractDevice,
{
    Ok(())
}
