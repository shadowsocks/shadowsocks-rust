use std::io;

use tun::platform::Device as TunDevice;

/// Set platform specific route configuration
pub async fn set_route_configuration(_device: &TunDevice) -> io::Result<()> {
    Ok(())
}
