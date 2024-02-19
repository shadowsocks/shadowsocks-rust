use std::{
    io::{self, ErrorKind},
    marker::Unpin,
    mem,
};

use log::{error, trace};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tun::{platform::Device as TunDevice, Device};
use windows_sys::Win32::{
    Foundation::NO_ERROR,
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry,
        GetBestInterface,
        MIB_IPFORWARDROW,
        MIB_IPROUTE_TYPE_INDIRECT,
    },
    Networking::WinSock::MIB_IPPROTO_NETMGMT,
};

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

    unsafe {
        // https://learn.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardrow
        let mut ipfrow: MIB_IPFORWARDROW = mem::zeroed();

        ipfrow.dwForwardDest = u32::from(tun_address);
        ipfrow.dwForwardMask = u32::from(tun_netmask);

        // Get ifindex of this inteface
        // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getbestinterface
        let mut if_index: u32 = 0;
        let ret = GetBestInterface(ipfrow.dwForwardDest, &mut if_index);
        if ret != NO_ERROR {
            error!("GetBestInterface failed, ret: {}, destination: {}", ret, tun_address);
            return Err(io::Error::new(ErrorKind::Other, format!("GetBestInterface {}", ret)));
        }
        ipfrow.dwForwardIfIndex = if_index;

        ipfrow.Anonymous1.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT as u32;
        ipfrow.Anonymous2.dwForwardProto = MIB_IPPROTO_NETMGMT as u32;

        let status = CreateIpForwardEntry(&ipfrow);
        if status != NO_ERROR {
            error!("CreateIpForwardEntry failed, status: {}", status);
            return Err(io::Error::new(
                ErrorKind::Other,
                format!("CreateIpForwardEntry {}", status),
            ));
        }
    }

    Ok(())
}
