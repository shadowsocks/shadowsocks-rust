//! UDP relay client

use std::{
    io,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use bytes::{Bytes, BytesMut};
use log::{debug, error, warn};
use tokio::net::UdpSocket;

use crate::{
    config::{ServerAddr, ServerConfig},
    context::Context,
    crypto::{CipherCategory, CipherType},
    relay::{socks5::Address, sys::create_udp_socket, utils::try_timeout},
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

/// UDP client for communicating with ShadowSocks' server
pub struct ServerClient {
    socket: UdpSocket,
    method: CipherType,
    key: Bytes,
}

impl ServerClient {
    /// Create a client to communicate with Shadowsocks' UDP server
    pub async fn new(context: &Context, svr_cfg: &ServerConfig) -> io::Result<ServerClient> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let socket = create_udp_socket(&local_addr).await?;
        match svr_cfg.addr() {
            ServerAddr::SocketAddr(ref remote_addr) => socket.connect(remote_addr).await?,
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context, dname, *port, |addr| { socket.connect(&addr).await })?;
            }
        };
        Ok(ServerClient {
            socket,
            method: svr_cfg.method(),
            key: svr_cfg.clone_key(),
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
        let mut send_buf = Vec::with_capacity(addr.serialized_len() + payload.len());
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);

        if let CipherCategory::None = self.method.category() {
            let send_len = try_timeout(self.socket.send(&send_buf), Some(timeout)).await?;
            if send_buf.len() != send_len {
                warn!(
                    "UDP server client send {} bytes, but actually sent {} bytes",
                    send_buf.len(),
                    send_len
                );
            }
        } else {
            let mut encrypt_buf = BytesMut::new();
            encrypt_payload(context, self.method, &self.key, &send_buf, &mut encrypt_buf)?;

            let send_len = try_timeout(self.socket.send(&encrypt_buf), Some(timeout)).await?;
            if encrypt_buf.len() != send_len {
                warn!(
                    "UDP server client send {} bytes, but actually sent {} bytes",
                    encrypt_buf.len(),
                    send_len
                );
            }
        }

        Ok(())
    }

    /// Receive packet from Shadowsocks' UDP server
    pub async fn recv_from(&mut self, context: &Context) -> io::Result<(Address, Vec<u8>)> {
        let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut recv_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let recv_n = try_timeout(self.socket.recv(&mut recv_buf), Some(timeout)).await?;

        let mut cur = if let CipherCategory::None = self.method.category() {
            recv_buf.truncate(recv_n);
            Cursor::new(recv_buf)
        } else {
            let decrypt_buf = match decrypt_payload(context, self.method, &self.key, &recv_buf[..recv_n])? {
                None => {
                    error!("UDP packet too short, received length {}", recv_n);
                    let err = io::Error::new(io::ErrorKind::InvalidData, "packet too short");
                    return Err(err);
                }
                Some(b) => b,
            };
            Cursor::new(decrypt_buf)
        };

        // SERVER -> CLIENT protocol: ADDRESS + PAYLOAD
        // FIXME: Address is ignored. Maybe useful in the future if we uses one common UdpSocket for communicate with remote server
        let addr = Address::read_from(&mut cur).await?;

        let mut payload = Vec::with_capacity(recv_n - cur.position() as usize);
        cur.read_to_end(&mut payload)?;

        debug!(
            "UDP server client recv {}, payload length {} bytes",
            addr,
            payload.len()
        );

        Ok((addr, payload))
    }
}
