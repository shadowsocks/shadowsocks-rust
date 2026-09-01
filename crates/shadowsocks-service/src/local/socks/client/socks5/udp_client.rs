//! Standalone SOCKS5 UDP client (single hop).

use std::io::{self, Cursor};

use bytes::{BufMut, BytesMut};
use shadowsocks::relay::socks5::{Address, Error as Socks5Error, UdpAssociateHeader};
use tokio::net::{ToSocketAddrs, UdpSocket};

use crate::net::Socks5Auth;

use super::tcp_client::Socks5TcpClient;

/// SOCKS5 UDP relay client.
pub struct Socks5UdpClient {
    socket: UdpSocket,
    // SOCKS5 spec requires the TCP control connection to be kept alive for
    // the lifetime of the UDP association.
    #[allow(dead_code)]
    assoc_client: Option<Socks5TcpClient>,
}

impl Socks5UdpClient {
    /// Bind a UDP socket on `addrs`. Call [`Self::associate`] before
    /// sending or receiving any data.
    pub async fn bind<A>(addrs: A) -> io::Result<Self>
    where
        A: ToSocketAddrs,
    {
        Ok(Self {
            socket: UdpSocket::bind(addrs).await?,
            assoc_client: None,
        })
    }

    /// Associate this UDP socket with a SOCKS5 proxy (no auth).
    pub async fn associate<P>(&mut self, proxy: P) -> Result<(), Socks5Error>
    where
        P: ToSocketAddrs,
    {
        self.associate_with_auth(proxy, &Socks5Auth::None).await
    }

    /// Associate with explicit authentication.
    pub async fn associate_with_auth<P>(&mut self, proxy: P, auth: &Socks5Auth) -> Result<(), Socks5Error>
    where
        P: ToSocketAddrs,
    {
        if self.assoc_client.is_some() {
            return Err(Socks5Error::IoError(io::Error::other("udp is already associated")));
        }

        let local_addr = self.socket.local_addr()?;
        let (assoc_client, proxy_addr) =
            Socks5TcpClient::udp_associate_with_auth(local_addr, proxy, auth).await?;
        match proxy_addr {
            Address::SocketAddress(sa) => self.socket.connect(sa).await?,
            // FIXME: domain-name relay address would require resolving via
            // the shadowsocks shared resolver; tokio's builtin DNS is used
            // here for backwards compatibility with the previous
            // implementation.
            Address::DomainNameAddress(ref dname, port) => self.socket.connect((dname.as_str(), port)).await?,
        }

        self.assoc_client = Some(assoc_client);
        Ok(())
    }

    /// Send `buf` to `target` (after wrapping with a SOCKS5 UDP header).
    pub async fn send_to<A>(&self, frag: u8, buf: &[u8], target: A) -> Result<usize, Socks5Error>
    where
        A: Into<Address>,
    {
        self.check_associated()?;

        let header = UdpAssociateHeader::new(frag, target.into());
        let header_len = header.serialized_len();
        let mut send_buf = BytesMut::with_capacity(header_len + buf.len());
        header.write_to_buf(&mut send_buf);
        send_buf.put_slice(buf);

        let n = self.socket.send(&send_buf).await?;
        Ok(n.saturating_sub(header_len))
    }

    /// Receive a SOCKS5 UDP datagram. The returned buffer slice has the
    /// SOCKS5 header stripped (data is shifted in-place).
    pub async fn recv_from(&self, recv_buf: &mut [u8]) -> Result<(usize, u8, Address), Socks5Error> {
        self.check_associated()?;

        let n = self.socket.recv(recv_buf).await?;
        let mut cur = Cursor::new(&recv_buf[..n]);
        let header = UdpAssociateHeader::read_from(&mut cur).await?;
        let pos = cur.position() as usize;
        recv_buf.copy_within(pos..n, 0);

        Ok((n - pos, header.frag, header.address))
    }

    fn check_associated(&self) -> io::Result<()> {
        if self.assoc_client.is_none() {
            return Err(io::Error::other("udp not associated"));
        }
        Ok(())
    }
}
