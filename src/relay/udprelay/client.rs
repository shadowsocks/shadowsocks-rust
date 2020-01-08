//! UDP relay client

use std::{
    io,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use bytes::{Bytes, BytesMut};
use log::{debug, error};
use tokio::net::UdpSocket;

use crate::{
    config::{ServerAddr, ServerConfig},
    context::Context,
    crypto::CipherType,
    relay::{socks5::Address, utils::try_timeout},
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    utils::create_socket,
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

/// UDP client for communicating with ShadowSocks' server
pub struct ServerClient {
    socket: UdpSocket,
    method: CipherType,
    key: Bytes,
    server_addr: ServerAddr,
}

impl ServerClient {
    /// Create a client to communicate with Shadowsocks' UDP server
    pub async fn new(svr_cfg: &ServerConfig) -> io::Result<ServerClient> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Ok(ServerClient {
            socket: create_socket(&local_addr).await?,
            method: svr_cfg.method(),
            key: svr_cfg.clone_key(),
            server_addr: svr_cfg.addr().clone(),
        })
    }

    /// Send a UDP packet to addr through proxy
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
        encrypt_payload(self.method, &self.key, &send_buf, &mut encrypt_buf)?;

        let send_len = match self.server_addr {
            ServerAddr::SocketAddr(ref remote_addr) => {
                try_timeout(self.socket.send_to(&encrypt_buf[..], remote_addr), Some(timeout)).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                use crate::relay::dns_resolver::resolve;

                let vec_ipaddr = resolve(context, dname, port, false).await?;
                assert!(!vec_ipaddr.is_empty());

                try_timeout(self.socket.send_to(&encrypt_buf[..], &vec_ipaddr[0]), Some(timeout)).await?
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

        let decrypt_buf = match decrypt_payload(self.method, &self.key, &recv_buf[..recv_n])? {
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
