//! IP packet encapsulation

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};

#[derive(Debug)]
pub enum IpPacket<T: AsRef<[u8]>> {
    Ipv4(Ipv4Packet<T>),
    Ipv6(Ipv6Packet<T>),
}

impl<T: AsRef<[u8]> + Copy> IpPacket<T> {
    pub fn new_checked(packet: T) -> smoltcp::wire::Result<Option<IpPacket<T>>> {
        let buffer = packet.as_ref();
        match IpVersion::of_packet(buffer)? {
            IpVersion::Ipv4 => Ok(Some(IpPacket::Ipv4(Ipv4Packet::new_checked(packet)?))),
            IpVersion::Ipv6 => Ok(Some(IpPacket::Ipv6(Ipv6Packet::new_checked(packet)?))),
        }
    }

    pub fn src_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(Ipv4Addr::from(packet.src_addr())),
            IpPacket::Ipv6(ref packet) => IpAddr::from(Ipv6Addr::from(packet.src_addr())),
        }
    }

    pub fn dst_addr(&self) -> IpAddr {
        match *self {
            IpPacket::Ipv4(ref packet) => IpAddr::from(Ipv4Addr::from(packet.dst_addr())),
            IpPacket::Ipv6(ref packet) => IpAddr::from(Ipv6Addr::from(packet.dst_addr())),
        }
    }

    pub fn protocol(&self) -> IpProtocol {
        match *self {
            IpPacket::Ipv4(ref packet) => packet.next_header(),
            IpPacket::Ipv6(ref packet) => packet.next_header(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> IpPacket<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        match *self {
            IpPacket::Ipv4(ref packet) => packet.payload(),
            IpPacket::Ipv6(ref packet) => packet.payload(),
        }
    }
}
