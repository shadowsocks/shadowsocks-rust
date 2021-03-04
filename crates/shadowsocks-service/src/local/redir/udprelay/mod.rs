//! UDP transparent proxy

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use log::{error, info, trace};
use shadowsocks::{
    lookup_then,
    relay::{socks5::Address, udprelay::MAXIMUM_UDP_PAYLOAD_SIZE},
};

use crate::{
    config::{ClientConfig, RedirType},
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UdpAssociationManager, UdpInboundWrite},
        redir::redir_ext::UdpSocketRedirExt,
    },
};

use self::sys::UdpRedirSocket;

mod sys;

#[derive(Clone)]
struct UdpRedirInboundWriter {
    redir_ty: RedirType,
}

#[async_trait]
impl UdpInboundWrite for UdpRedirInboundWriter {
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        let addr = match *remote_addr {
            Address::SocketAddress(sa) => sa,
            Address::DomainNameAddress(..) => {
                let err = io::Error::new(
                    ErrorKind::InvalidInput,
                    "redir destination must not be an domain name address",
                );
                return Err(err);
            }
        };

        // Create a socket binds to destination addr
        // This only works for systems that supports binding to non-local addresses
        //
        // This socket has to set SO_REUSEADDR and SO_REUSEPORT.
        // Outbound addresses could be connected from different source addresses.
        let inbound = UdpRedirSocket::bind_nonlocal(self.redir_ty, addr)?;

        // Send back to client
        inbound.send_to(data, peer_addr).await.map(|_| ())
    }
}

pub struct UdpRedir {
    context: Arc<ServiceContext>,
    redir_ty: RedirType,
    time_to_live: Option<Duration>,
    capacity: Option<usize>,
}

impl UdpRedir {
    pub fn new(
        context: Arc<ServiceContext>,
        redir_ty: RedirType,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
    ) -> UdpRedir {
        UdpRedir {
            context,
            redir_ty,
            time_to_live,
            capacity,
        }
    }

    pub async fn run(&self, client_config: &ClientConfig, balancer: PingBalancer) -> io::Result<()> {
        let listener = match *client_config {
            ClientConfig::SocketAddr(ref saddr) => UdpRedirSocket::listen(self.redir_ty, *saddr)?,
            ClientConfig::DomainName(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |addr| {
                    UdpRedirSocket::listen(self.redir_ty, addr)
                })?
                .1
            }
        };

        let local_addr = listener.local_addr().expect("determine port bound to");
        info!("shadowsocks UDP redirect listening on {}", local_addr);

        let manager = UdpAssociationManager::new(
            self.context.clone(),
            UdpRedirInboundWriter {
                redir_ty: self.redir_ty,
            },
            self.time_to_live,
            self.capacity,
            balancer,
        );

        let mut pkt_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (recv_len, src, dst) = match listener.recv_dest_from(&mut pkt_buf).await {
                Ok(o) => o,
                Err(err) => {
                    error!("recv_dest_from failed with err: {}", err);
                    continue;
                }
            };

            // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
            // Copy bytes, because udp_associate runs in another tokio Task
            let pkt = &pkt_buf[..recv_len];

            trace!(
                "received UDP packet from {}, destination {}, length {} bytes",
                src,
                dst,
                recv_len
            );

            if recv_len == 0 {
                // For windows, it will generate a ICMP Port Unreachable Message
                // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom
                // Which will result in recv_from return 0.
                //
                // It cannot be solved here, because `WSAGetLastError` is already set.
                //
                // See `relay::udprelay::utils::create_socket` for more detail.
                continue;
            }

            if let Err(err) = manager.send_to(src, Address::from(dst), pkt).await {
                error!(
                    "udp packet relay {} -> {} with {} bytes failed, error: {}",
                    src,
                    dst,
                    pkt.len(),
                    err
                );
            }
        }
    }
}
