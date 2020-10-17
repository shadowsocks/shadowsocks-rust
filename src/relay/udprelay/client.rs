//! UDP relay client

use std::{
    io,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use bytes::{BufMut, Bytes, BytesMut};
use log::{debug, error, warn};
use tokio::net::UdpSocket;

use crate::{
    config::{ServerAddr, ServerConfig},
    context::Context,
    crypto::{CipherCategory, CipherType},
    relay::{
        socks5::{Address, UdpAssociateHeader},
        sys::create_udp_socket,
        tcprelay::client::Socks5Client as Socks5TcpClient,
        utils::try_timeout,
    },
};

use super::{
    crypto_io::{decrypt_payload, encrypt_payload},
    DEFAULT_TIMEOUT,
    MAXIMUM_UDP_PAYLOAD_SIZE,
};

/// Socks5 proxy client
pub struct Socks5Client {
    socket: UdpSocket,

    // Socks5 protocol requires to keep this TCP connection alive
    // Theoretically if this connection is broken, the association is broken too, but the UDP Socks5 server in this crate doesn't behave like that
    #[allow(dead_code)]
    assoc_client: Socks5TcpClient,
}

impl Socks5Client {
    /// Create a new UDP associate to `proxy`
    pub async fn associate(proxy: &SocketAddr) -> io::Result<Socks5Client> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let socket = create_udp_socket(&local_addr).await?;

        // The actual bind address, tell the proxy that I am going to send packets from this address
        let local_addr = socket.local_addr()?;

        let (assoc_client, proxy_addr) = Socks5TcpClient::udp_associate(local_addr, proxy).await?;
        match proxy_addr {
            Address::SocketAddress(sa) => socket.connect(sa).await?,
            // FIXME: `connect` will use tokio's builtin DNS resolver.
            // But if we want to use `trust-dns`, we have to initialize a `Context` instance (for the global `AsyncResolver` instance)
            Address::DomainNameAddress(ref dname, port) => socket.connect((dname.as_str(), port)).await?,
        }

        Ok(Socks5Client { socket, assoc_client })
    }

    /// Returns a future that sends data on the socket to the given address.
    pub async fn send_to<A>(&self, buf: &[u8], target: A) -> io::Result<usize>
    where
        A: Into<Address>,
    {
        // ShadowSocks doesn't support UDP fragmentation, so it will always be 0
        let header = UdpAssociateHeader::new(0, target.into());
        let header_len = header.serialized_len();
        let mut send_buf = BytesMut::with_capacity(header.serialized_len() + buf.len());
        header.write_to_buf(&mut send_buf);
        send_buf.put_slice(buf);

        let n = self.socket.send(&send_buf).await?;
        Ok(if n <= header_len { 0 } else { n - header_len })
    }

    /// Returns a future that receives a single datagram on the socket. On success, the future resolves to the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array buf of sufficient size to hold the message bytes.
    /// If a message is too long to fit in the supplied buffer, excess bytes may be discarded.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let mut recv_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let n = self.socket.recv(&mut recv_buf).await?;

        // Address + Payload
        let mut cur = Cursor::new(&recv_buf[..n]);

        let header = UdpAssociateHeader::read_from(&mut cur).await?;
        let n = cur.read(buf)?;

        Ok((n, header.address))
    }
}

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

    async fn pack_req(
        method: CipherType,
        key: &Bytes,
        context: &Context,
        addr: &Address,
        payload: &[u8],
    ) -> io::Result<Bytes> {
        // CLIENT -> SERVER protocol: ADDRESS + PAYLOAD
        let mut send_buf = BytesMut::with_capacity(addr.serialized_len() + payload.len());
        addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(payload);
        if let CipherCategory::None = method.category() {
            Ok(send_buf.freeze())
        } else {
            let mut encrypt_buf = BytesMut::with_capacity(send_buf.len());
            encrypt_payload(context, method, key, &send_buf, &mut encrypt_buf)?;
            Ok(encrypt_buf.freeze())
        }
    }

    /// Send a UDP packet to addr through proxy
    pub async fn send_to(&self, context: &Context, addr: &Address, payload: &[u8]) -> io::Result<()> {
        debug!(
            "UDP server client send to {}, payload length {} bytes",
            addr,
            payload.len()
        );

        let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        let send_buf = Self::pack_req(self.method, &self.key, context, addr, payload).await?;

        let send_len = try_timeout(self.socket.send(&send_buf), Some(timeout)).await?;
        if send_buf.len() != send_len {
            warn!(
                "UDP server client send {} bytes, but actually sent {} bytes",
                send_buf.len(),
                send_len
            );
        }

        Ok(())
    }

    async fn parse_resp(
        context: &Context,
        method: CipherType,
        key: &Bytes,
        recv_buf: &[u8],
    ) -> io::Result<(Address, Vec<u8>)> {
        let mut cur = if let CipherCategory::None = method.category() {
            Cursor::new(recv_buf.to_vec())
        } else {
            let decrypt_buf = match decrypt_payload(context, method, key, recv_buf)? {
                None => {
                    error!("UDP packet too short, received length {}", recv_buf.len());
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

        let mut payload = Vec::with_capacity(recv_buf.len() - cur.position() as usize);
        cur.read_to_end(&mut payload)?;

        debug!(
            "UDP server client recv {}, payload length {} bytes",
            addr,
            payload.len()
        );

        Ok((addr, payload))
    }

    /// Receive packet from Shadowsocks' UDP server
    pub async fn recv_from(&self, context: &Context) -> io::Result<(Address, Vec<u8>)> {
        let timeout = context.config().udp_timeout.unwrap_or(DEFAULT_TIMEOUT);

        // Waiting for response from server SERVER -> CLIENT
        // Packet length is limited by MAXIMUM_UDP_PAYLOAD_SIZE, excess bytes will be discarded.
        let mut recv_buf = vec![0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let recv_n = try_timeout(self.socket.recv(&mut recv_buf), Some(timeout)).await?;
        let (addr, payload) = Self::parse_resp(context, self.method, &self.key, &recv_buf[..recv_n]).await?;
        Ok((addr, payload))
    }
}
