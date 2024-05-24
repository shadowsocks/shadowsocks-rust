use std::io;

use tun::Device;

/// Set platform specific route configuration
pub async fn set_route_configuration<Q>(_: &mut (dyn Device<Queue = Q> + Send)) -> io::Result<()>
where
    Q: Read + Write,
{
    Ok(())
}
