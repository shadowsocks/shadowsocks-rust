//! UDP relay client

use std::{
    io,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use bytes::BytesMut;
use log::{debug, error};
use tokio::net::UdpSocket;

use crate::{
    config::{ServerAddr, ServerConfig},
    context::Context,
    relay::{socks5::Address, utils::try_timeout},
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    utils::create_socket,
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

pub struct ServerClient {
    socket: UdpSocket,
    svr_cfg: Arc<ServerConfig>,
}

impl ServerClient {
    /// Create a client to communicate with Shadowsocks' UDP server
    pub async fn new(svr_cfg: Arc<ServerConfig>) -> io::Result<ServerClient> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Ok(ServerClient {
            socket: create_socket(&local_addr).await?,
            svr_cfg,
        })
    }

    pub async fn send_to(&mut self, context: &Context, addr: &Address, payload: &[u8]) -> io::Result<()> {
        debug!(
            "UDP server client send to {}, payload length {} bytes",
            addr,
            payload.len()
        );

        let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = Vec::new();
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        let mut encrypt_buf = BytesMut::new();
        encrypt_payload(self.svr_cfg.method(), self.svr_cfg.key(), &send_buf, &mut encrypt_buf)?;

        let send_len = match self.svr_cfg.addr() {
            ServerAddr::SocketAddr(ref remote_addr) => {
                try_timeout(self.socket.send_to(&encrypt_buf[..], remote_addr), Some(timeout)).await?
            }
            #[cfg(feature = "trust-dns")]
            ServerAddr::DomainName(ref dname, port) => {
                use crate::relay::dns_resolver::resolve;

                let vec_ipaddr = resolve(context, dname, *port, false).await?;
                assert!(!vec_ipaddr.is_empty());

                try_timeout(self.socket.send_to(&encrypt_buf[..], &vec_ipaddr[0]), Some(timeout)).await?
            }
            #[cfg(not(feature = "trust-dns"))]
            ServerAddr::DomainName(ref dname, port) => {
                // try_timeout(self.socket.send_to(&encrypt_buf[..], (dname.as_str(), port)), Some(timeout)).await?
                unimplemented!(
                    "tokio's UdpSocket SendHalf doesn't support ToSocketAddrs, {}:{}",
                    dname,
                    port
                );
            }
        };

        assert_eq!(encrypt_buf.len(), send_len);

        Ok(())
    }

    /// Receive packet from Shadowsocks' UDP server
    pub async fn recv_from(&mut self, context: &Context) -> io::Result<(Address, Vec<u8>)> {
        let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut recv_buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (recv_n, ..) = try_timeout(self.socket.recv_from(&mut recv_buf), Some(timeout)).await?;

        let decrypt_buf = match decrypt_payload(self.svr_cfg.method(), self.svr_cfg.key(), &recv_buf[..recv_n])? {
            None => {
                error!("UDP packet too short, received length {}", recv_n);
                let err = io::Error::new(io::ErrorKind::InvalidData, "packet too short");
                return Err(err);
            }
            Some(b) => b,
        };
        // SERVER -> CLIENT protocol: ADDRESS + PAYLOAD
        let mut cur = Cursor::new(decrypt_buf);
        // FIXME: Address is ignored. Maybe useful in the future if we uses one common UdpSocket for communicate with remote server
        let addr = Address::read_from(&mut cur).await?;

        let mut payload = Vec::new();
        cur.read_to_end(&mut payload)?;

        debug!(
            "UDP server client recv_from {}, payload length {} bytes",
            addr,
            payload.len()
        );

        Ok((addr, payload))
    }
}
