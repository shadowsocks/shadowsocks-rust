//! Shadowsocks Local server serving on a Tun interface

use std::{
    io::{self, Cursor, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use etherparse::{IpHeader, PacketHeaders, ReadError, TransportHeader};
use ipnet::{IpNet, Ipv4Net};
use log::{error, info, trace};
use shadowsocks::net::TcpListener;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time,
};
use tun::{AsyncDevice, Configuration as TunConfiguration, Device, IntoAddress, Layer, TunPacket};

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

use self::{sys::IFF_PI_PREFIX_LEN, tcp::TcpTun, udp::UdpTun};

mod sys;
mod tcp;
mod udp;

pub struct TunBuilder {
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    tun_config: TunConfiguration,
}

impl TunBuilder {
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer) -> TunBuilder {
        TunBuilder {
            context,
            balancer,
            tun_config: TunConfiguration::default(),
        }
    }

    pub fn address(mut self, addr: IpNet) -> TunBuilder {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
        self
    }

    pub async fn build(mut self) -> io::Result<Tun> {
        self.tun_config.layer(Layer::L3).up();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.tun_config.platform(|tun_config| {
            // Enable Packet Information for the framed API (do not set IFF_NO_PI)
            tun_config.packet_information(true);
        });

        let device = match tun::create_as_async(&self.tun_config) {
            Ok(d) => d,
            Err(err) => {
                error!("failed to create tun device, error: {:?}", err);
                return Err(io::Error::new(ErrorKind::Other, err));
            }
        };

        let tun_address = match device.get_ref().address() {
            Ok(t) => t,
            Err(err) => {
                error!("failed to get tun address, err: {}", err);
                return Err(io::Error::new(ErrorKind::Other, err));
            }
        };

        let tun_netmask = match device.get_ref().netmask() {
            Ok(m) => m,
            Err(err) => {
                error!("failed to get netmask, err: {}", err);
                return Err(io::Error::new(ErrorKind::Other, err));
            }
        };

        trace!("tun address: {}, netmask: {}", tun_address, tun_netmask);

        let tun_netmask_u32: u32 = tun_netmask.into();

        let tun_network = Ipv4Net::new(tun_address, tun_netmask_u32.leading_ones() as u8).expect("Ipv4Net::new");

        let (tun_tx, tun_rx) = mpsc::channel(64);

        Ok(Tun {
            device,
            tun_rx,
            tcp: TcpTun::new(self.context.clone(), tun_network.into(), self.balancer).await?,
            udp: UdpTun::new(self.context, tun_tx),
        })
    }
}

pub struct Tun {
    device: AsyncDevice,
    tun_rx: mpsc::Receiver<TunPacket>,
    tcp: TcpTun,
    udp: UdpTun,
}

impl Tun {
    pub async fn run(mut self) -> io::Result<()> {
        let mtu = self.device.get_ref().mtu().expect("mtu");
        assert!(mtu > 0 && mtu as usize > IFF_PI_PREFIX_LEN);

        info!(
            "shadowsocks tun device {}, address {}, netmask {}, mtu {}",
            self.device.get_ref().name(),
            self.device.get_ref().address().expect("address"),
            self.device.get_ref().netmask().expect("netmask"),
            mtu,
        );

        let mut packet_buffer = vec![0u8; mtu as usize + IFF_PI_PREFIX_LEN].into_boxed_slice();

        loop {
            // tun device
            let n = self.device.read(&mut packet_buffer).await?;

            if n <= IFF_PI_PREFIX_LEN {
                error!(
                    "[TUN] packet too short, packet: {:?}",
                    ByteStr::new(&packet_buffer[..n])
                );
                continue;
            }

            let packet = &mut packet_buffer[IFF_PI_PREFIX_LEN..n];
            trace!("[TUN] received IP packet {:?}", ByteStr::new(packet));

            if self.handle_packet(packet).await? {
                self.device.write_all(&packet_buffer[..n]).await?;
            }
        }
    }

    async fn handle_packet(&mut self, packet: &mut [u8]) -> io::Result<bool> {
        let mut ph = match PacketHeaders::from_ip_slice(packet) {
            Ok(ph) => ph,
            Err(ReadError::IoError(err)) => return Err(err),
            Err(err) => {
                error!("invalid IP packet, error: {:?}, {:?}", err, ByteStr::new(packet));
                return Err(io::Error::new(ErrorKind::Other, err));
            }
        };

        let payload_len = ph.payload.len();

        let mut ip_header = match ph.ip {
            Some(ref mut i) => i,
            None => {
                error!("unrecognized ethernet packet {:?}", ph);
                return Err(io::Error::new(ErrorKind::Other, "unrecognized ethernet packet"));
            }
        };

        let (src_ip, dst_ip) = match *ip_header {
            IpHeader::Version4(ref v4) => (Ipv4Addr::from(v4.source).into(), Ipv4Addr::from(v4.destination).into()),
            IpHeader::Version6(ref v6) => (Ipv6Addr::from(v6.source).into(), Ipv6Addr::from(v6.destination).into()),
        };

        match ph.transport {
            Some(TransportHeader::Tcp(ref mut tcp_header)) => {
                let src_addr = SocketAddr::new(src_ip, tcp_header.source_port);
                let dst_addr = SocketAddr::new(dst_ip, tcp_header.destination_port);

                let (mod_src_addr, mod_dst_addr) = match self.tcp.handle_packet(src_addr, dst_addr, &tcp_header).await {
                    Ok(a) => a,
                    Err(err) => {
                        error!("handle IP packet failed, error: {}", err);
                        return Ok(false);
                    }
                };

                // Replaces IP_HEADER, TRANSPORT_HEADER directly into packet
                match (mod_src_addr, &mut ip_header) {
                    (SocketAddr::V4(v4addr), IpHeader::Version4(v4ip)) => v4ip.source = v4addr.ip().octets(),
                    (SocketAddr::V6(v6addr), IpHeader::Version6(v6ip)) => v6ip.source = v6addr.ip().octets(),
                    _ => unreachable!("modified saddr not match"),
                }
                tcp_header.source_port = mod_src_addr.port();
                match (mod_dst_addr, &mut ip_header) {
                    (SocketAddr::V4(v4addr), IpHeader::Version4(v4ip)) => v4ip.destination = v4addr.ip().octets(),
                    (SocketAddr::V6(v6addr), IpHeader::Version6(v6ip)) => v6ip.destination = v6addr.ip().octets(),
                    _ => unreachable!("modified daddr not match"),
                }
                tcp_header.destination_port = mod_dst_addr.port();
                match ip_header {
                    IpHeader::Version4(v4) => {
                        tcp_header.checksum = tcp_header
                            .calc_checksum_ipv4(v4, ph.payload)
                            .expect("calc_checksum_ipv4")
                    }
                    IpHeader::Version6(v6) => {
                        tcp_header.checksum = tcp_header
                            .calc_checksum_ipv6(v6, ph.payload)
                            .expect("calc_checksum_ipv6")
                    }
                }

                let (headers, _) = packet.split_at_mut(packet.len() - payload_len);
                let mut cursor = Cursor::new(headers);

                ip_header.write(&mut cursor).expect("ip_header.write");
                tcp_header.write(&mut cursor).expect("tcp_header.write");

                Ok(true)
            }
            Some(TransportHeader::Udp(ref udp_header)) => {
                // UDP proxies directly

                let src_addr = SocketAddr::new(src_ip, udp_header.source_port);
                let dst_addr = SocketAddr::new(dst_ip, udp_header.destination_port);

                Ok(false)
            }
            None => {
                error!("no transport layer in ethernet packet {:?}", ph);
                Err(io::Error::new(
                    ErrorKind::Other,
                    "no transport layer in ethernet packet",
                ))
            }
        }
    }
}
