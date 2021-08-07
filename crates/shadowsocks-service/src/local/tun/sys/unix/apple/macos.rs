use std::io::{self, ErrorKind};

use log::{debug, error};
use tokio::process::Command;
use tun::{platform::Device as TunDevice, Device};

/// Set platform specific route configuration
pub async fn set_route_configuration(device: &TunDevice) -> io::Result<()> {
    let tun_address = match device.address() {
        Ok(t) => t,
        Err(err) => {
            error!("tun device doesn't have address, error: {}", err);
            return Err(io::Error::new(ErrorKind::Other, err));
        }
    };

    let tun_netmask = match device.netmask() {
        Ok(m) => m,
        Err(err) => {
            error!("tun device doesn't have netmask, error: {}", err);
            return Err(io::Error::new(ErrorKind::Other, err));
        }
    };

    let tun_name = device.name();

    // routing packets that saddr & daddr are in the subnet of the Tun interface
    //
    // This is only required for the TCP tunnel, and it is the default behavior on Linux

    let mut cmd = Command::new("route");
    cmd.arg("add")
        .arg("-net")
        .arg(tun_address.to_string())
        .arg("-netmask")
        .arg(tun_netmask.to_string())
        .arg("-interface")
        .arg(tun_name)
        .kill_on_drop(true);

    let child = cmd.spawn()?;
    let output = child.wait_with_output().await?;
    if output.status.success() {
        debug!("set route successfully. {} -> {}", tun_address, tun_name);

        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::Other,
                     format!("failed to set route. output.status: {}, try to manually set it by running `route add -net {} -netmask {} -interface {}`",
                                   output.status, tun_address, tun_netmask, tun_name)))
    }
}
