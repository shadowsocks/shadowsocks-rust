//! Shadowsocks Local server serving on a Tun interface

#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use ipnet::IpNet;
use log::{debug, error, info, trace, warn};
use shadowsocks::config::Mode;
use smoltcp::wire::{IpProtocol, TcpPacket, UdpPacket};
use tokio::io::AsyncReadExt;
use tun::{AsyncDevice, Configuration as TunConfiguration, Device as TunDevice, Error as TunError, Layer};

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

use self::{
    ip_packet::IpPacket,
    sys::{write_packet_with_pi, IFF_PI_PREFIX_LEN},
    tcp::TcpTun,
    udp::UdpTun,
};

mod ip_packet;
mod sys;
mod tcp;
mod udp;
mod virt_device;

pub struct TunBuilder {
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    tun_config: TunConfiguration,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    mode: Mode,
}

impl TunBuilder {
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer) -> TunBuilder {
        TunBuilder {
            context,
            balancer,
            tun_config: TunConfiguration::default(),
            udp_expiry_duration: None,
            udp_capacity: None,
            mode: Mode::TcpOnly,
        }
    }

    pub fn address(mut self, addr: IpNet) -> TunBuilder {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
        self
    }

    pub fn name(mut self, name: &str) -> TunBuilder {
        self.tun_config.name(name);
        self
    }

    #[cfg(unix)]
    pub fn file_descriptor(mut self, fd: RawFd) -> TunBuilder {
        self.tun_config.raw_fd(fd);
        self
    }

    pub fn udp_expiry_duration(mut self, udp_expiry_duration: Duration) -> TunBuilder {
        self.udp_expiry_duration = Some(udp_expiry_duration);
        self
    }

    pub fn udp_capacity(mut self, udp_capacity: usize) -> TunBuilder {
        self.udp_capacity = Some(udp_capacity);
        self
    }

    pub fn mode(mut self, mode: Mode) -> TunBuilder {
        self.mode = mode;
        self
    }

    pub async fn build(mut self) -> io::Result<Tun> {
        self.tun_config.layer(Layer::L3).up();

        #[cfg(any(target_os = "linux"))]
        self.tun_config.platform(|tun_config| {
            // IFF_NO_PI preventing excessive buffer reallocating
            tun_config.packet_information(false);
        });

        let device = match tun::create_as_async(&self.tun_config) {
            Ok(d) => d,
            Err(TunError::Io(err)) => return Err(err),
            Err(err) => return Err(io::Error::new(ErrorKind::Other, err)),
        };

        let udp = UdpTun::new(
            self.context.clone(),
            self.balancer.clone(),
            self.udp_expiry_duration,
            self.udp_capacity,
        );

        let tcp = TcpTun::new(
            self.context,
            self.balancer,
            device.get_ref().mtu().unwrap_or(1500) as u32,
        );

        Ok(Tun {
            device,
            tcp,
            udp,
            mode: self.mode,
        })
    }
}

pub struct Tun {
    device: AsyncDevice,
    tcp: TcpTun,
    udp: UdpTun,
    mode: Mode,
}

impl Tun {
    pub async fn run(mut self) -> io::Result<()> {
        let mtu = self.device.get_ref().mtu().expect("mtu");
        assert!(mtu > 0 && mtu as usize > IFF_PI_PREFIX_LEN);

        info!(
            "shadowsocks tun device {}, mtu {}, mode {}",
            self.device.get_ref().name(),
            mtu,
            self.mode,
        );

        let mut packet_buffer = vec![0u8; mtu as usize + IFF_PI_PREFIX_LEN].into_boxed_slice();

        loop {
            tokio::select! {
                // tun device
                n = self.device.read(&mut packet_buffer) => {
                    let n = n?;

                    if n <= IFF_PI_PREFIX_LEN {
                        error!(
                            "[TUN] packet too short, packet: {:?}",
                            ByteStr::new(&packet_buffer[..n])
                        );
                        continue;
                    }

                    let packet = &mut packet_buffer[IFF_PI_PREFIX_LEN..n];
                    trace!("[TUN] received IP packet {:?}", ByteStr::new(packet));

                    if let Err(err) = self.handle_tun_frame(packet).await {
                        error!("[TUN] handle IP frame failed, error: {}", err);
                    }
                }

                // UDP channel sent back
                packet = self.udp.recv_packet() => {
                    if let Err(err) = write_packet_with_pi(&mut self.device, &packet).await {
                        error!("[TUN] failed to set packet information, error: {}, {:?}", err, ByteStr::new(&packet));
                    }
                }

                // TCP channel sent back
                packet = self.tcp.recv_packet() => {
                    if let Err(err) = write_packet_with_pi(&mut self.device, &packet).await {
                        error!("[TUN] failed to set packet information, error: {}, {:?}", err, ByteStr::new(&packet));
                    }
                }
            }
        }
    }

    async fn handle_tun_frame(&mut self, frame: &[u8]) -> smoltcp::Result<()> {
        let packet = match IpPacket::new_checked(frame) {
            Some(packet) => packet,
            None => {
                warn!("unrecognized IP packet {:?}", ByteStr::new(frame));
                return Ok(());
            }
        };

        match packet.protocol() {
            IpProtocol::Tcp => {
                let tcp_packet = match TcpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid TCP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();

                let src_addr = SocketAddr::new(packet.src_addr(), src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                trace!("[TUN] TCP packet {} -> {} {}", src_addr, dst_addr, tcp_packet);

                // TCP first handshake packet.
                if let Err(err) = self.tcp.handle_packet(src_addr, dst_addr, &tcp_packet).await {
                    error!(
                        "handle TCP packet failed, error: {}, {} <-> {}, packet: {:?}",
                        err, src_addr, dst_addr, tcp_packet
                    );
                }

                self.tcp.drive_interface_state(frame);
            }
            IpProtocol::Udp => {
                let udp_packet = match UdpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid UDP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = udp_packet.src_port();
                let dst_port = udp_packet.dst_port();

                let src_addr = SocketAddr::new(packet.src_addr(), src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                let payload = udp_packet.payload();
                trace!("[TUN] UDP packet {} -> {} {}", src_addr, dst_addr, udp_packet);

                if let Err(err) = self.udp.handle_packet(src_addr, dst_addr, payload).await {
                    error!("handle UDP packet failed, err: {}, packet: {:?}", err, udp_packet);
                }
            }
            IpProtocol::Icmp => {}
            _ => {
                debug!("IP packet ignored (protocol: {:?})", packet.protocol());
                return Ok(());
            }
        }

        Ok(())
    }

    // async fn handle_packet(&mut self, packet: &mut [u8]) -> io::Result<bool> {
    //     let mut ph = match PacketHeaders::from_ip_slice(packet) {
    //         Ok(ph) => ph,
    //         Err(ReadError::IoError(err)) => return Err(err),
    //         Err(err) => {
    //             error!("invalid IP packet, error: {:?}, {:?}", err, ByteStr::new(packet));
    //             return Err(io::Error::new(ErrorKind::Other, err));
    //         }
    //     };

    //     let payload_len = ph.payload.len();

    //     let mut ip_header = match ph.ip {
    //         Some(ref mut i) => i,
    //         None => {
    //             error!("unrecognized ethernet packet {:?}", ph);
    //             return Err(io::Error::new(ErrorKind::Other, "unrecognized ethernet packet"));
    //         }
    //     };

    //     let (src_ip, dst_ip) = match *ip_header {
    //         IpHeader::Version4(ref v4, ..) => (Ipv4Addr::from(v4.source).into(), Ipv4Addr::from(v4.destination).into()),
    //         IpHeader::Version6(ref v6, ..) => (Ipv6Addr::from(v6.source).into(), Ipv6Addr::from(v6.destination).into()),
    //     };

    //     match ph.transport {
    //         Some(TransportHeader::Tcp(ref mut tcp_header)) => {
    //             let tcp = match self.tcp {
    //                 Some(ref mut tcp) => tcp,
    //                 None => return Ok(false),
    //             };

    //             let src_addr = SocketAddr::new(src_ip, tcp_header.source_port);
    //             let dst_addr = SocketAddr::new(dst_ip, tcp_header.destination_port);

    //             let (mod_src_addr, mod_dst_addr) = match tcp.handle_packet(src_addr, dst_addr, tcp_header).await {
    //                 Ok(Some(a)) => a,
    //                 Ok(None) => return Ok(false),
    //                 Err(err) => {
    //                     error!("handle TCP/IP packet failed, error: {}", err);
    //                     return Ok(false);
    //                 }
    //             };

    //             // Replaces IP_HEADER, TRANSPORT_HEADER directly into packet
    //             match (mod_src_addr, &mut ip_header) {
    //                 (SocketAddr::V4(v4addr), IpHeader::Version4(v4ip, ..)) => v4ip.source = v4addr.ip().octets(),
    //                 (SocketAddr::V6(v6addr), IpHeader::Version6(v6ip, ..)) => v6ip.source = v6addr.ip().octets(),
    //                 _ => {
    //                     unreachable!(
    //                         "modified TCP saddr not match, addr: {}, header: {:?}",
    //                         mod_src_addr, ip_header
    //                     );
    //                 }
    //             }
    //             tcp_header.source_port = mod_src_addr.port();
    //             match (mod_dst_addr, &mut ip_header) {
    //                 (SocketAddr::V4(v4addr), IpHeader::Version4(v4ip, ..)) => v4ip.destination = v4addr.ip().octets(),
    //                 (SocketAddr::V6(v6addr), IpHeader::Version6(v6ip, ..)) => v6ip.destination = v6addr.ip().octets(),
    //                 _ => {
    //                     unreachable!(
    //                         "modified TCP daddr not match, addr: {}, header: {:?}",
    //                         mod_dst_addr, ip_header
    //                     );
    //                 }
    //             }
    //             tcp_header.destination_port = mod_dst_addr.port();
    //             match ip_header {
    //                 IpHeader::Version4(v4, ..) => {
    //                     tcp_header.checksum = tcp_header
    //                         .calc_checksum_ipv4(v4, ph.payload)
    //                         .expect("calc_checksum_ipv4")
    //                 }
    //                 IpHeader::Version6(v6, ..) => {
    //                     tcp_header.checksum = tcp_header
    //                         .calc_checksum_ipv6(v6, ph.payload)
    //                         .expect("calc_checksum_ipv6")
    //                 }
    //             }

    //             let (headers, _) = packet.split_at_mut(packet.len() - payload_len);
    //             let mut cursor = Cursor::new(headers);

    //             ip_header.write(&mut cursor).expect("ip_header.write");
    //             tcp_header.write(&mut cursor).expect("tcp_header.write");

    //             Ok(true)
    //         }
    //         Some(TransportHeader::Udp(ref udp_header)) => {
    //             // UDP proxies directly
    //             let udp = match self.udp {
    //                 Some(ref mut udp) => udp,
    //                 None => return Ok(false),
    //             };

    //             let src_addr = SocketAddr::new(src_ip, udp_header.source_port);
    //             let dst_addr = SocketAddr::new(dst_ip, udp_header.destination_port);

    //             if let Err(err) = udp.handle_packet(src_addr, dst_addr, ph.payload).await {
    //                 error!("handle UDP/IP packet failed, error: {}", err);
    //             }

    //             Ok(false)
    //         }
    //         None => {
    //             trace!("no transport layer in ethernet packet {:?}", ph);
    //             Ok(false)
    //         }
    //     }
    // }
}
