//! Socks5 protocol definition (RFC1928)
//!
//! Implements [SOCKS Protocol Version 5](https://www.ietf.org/rfc/rfc1928.txt) proxy protocol

use std::{
    convert::From,
    error,
    fmt::{self, Debug, Formatter},
    io::{self, Cursor},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    str::FromStr,
    u8,
    vec,
};

use bytes::{buf::BufExt, Buf, BufMut, BytesMut};
use tokio::prelude::*;

pub use self::consts::{
    SOCKS5_AUTH_METHOD_GSSAPI,
    SOCKS5_AUTH_METHOD_NONE,
    SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
    SOCKS5_AUTH_METHOD_PASSWORD,
};

#[rustfmt::skip]
mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI:               u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// SOCKS5 command
#[derive(Clone, Debug, Copy)]
pub enum Command {
    /// CONNECT command (TCP tunnel)
    TcpConnect,
    /// BIND command (Not supported in ShadowSocks)
    TcpBind,
    /// UDP ASSOCIATE command
    UdpAssociate,
}

impl Command {
    #[inline]
    #[rustfmt::skip]
    fn as_u8(self) -> u8 {
        match self {
            Command::TcpConnect   => consts::SOCKS5_CMD_TCP_CONNECT,
            Command::TcpBind      => consts::SOCKS5_CMD_TCP_BIND,
            Command::UdpAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    #[rustfmt::skip]
    fn from_u8(code: u8) -> Option<Command> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT   => Some(Command::TcpConnect),
            consts::SOCKS5_CMD_TCP_BIND      => Some(Command::TcpBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _                                => None,
        }
    }
}

/// SOCKS5 reply code
#[derive(Clone, Debug, Copy)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,

    OtherReply(u8),
}

impl Reply {
    #[inline]
    #[rustfmt::skip]
    fn as_u8(self) -> u8 {
        match self {
            Reply::Succeeded               => consts::SOCKS5_REPLY_SUCCEEDED,
            Reply::GeneralFailure          => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            Reply::ConnectionNotAllowed    => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Reply::NetworkUnreachable      => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Reply::HostUnreachable         => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            Reply::ConnectionRefused       => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            Reply::TtlExpired              => consts::SOCKS5_REPLY_TTL_EXPIRED,
            Reply::CommandNotSupported     => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Reply::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            Reply::OtherReply(c)           => c,
        }
    }

    #[inline]
    #[rustfmt::skip]
    fn from_u8(code: u8) -> Reply {
        match code {
            consts::SOCKS5_REPLY_SUCCEEDED                  => Reply::Succeeded,
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => Reply::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => Reply::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => Reply::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => Reply::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => Reply::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED                => Reply::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => Reply::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Reply::AddressTypeNotSupported,
            _                                               => Reply::OtherReply(code),
        }
    }
}

impl fmt::Display for Reply {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Reply::Succeeded               => write!(f, "Succeeded"),
            Reply::AddressTypeNotSupported => write!(f, "Address type not supported"),
            Reply::CommandNotSupported     => write!(f, "Command not supported"),
            Reply::ConnectionNotAllowed    => write!(f, "Connection not allowed"),
            Reply::ConnectionRefused       => write!(f, "Connection refused"),
            Reply::GeneralFailure          => write!(f, "General failure"),
            Reply::HostUnreachable         => write!(f, "Host unreachable"),
            Reply::NetworkUnreachable      => write!(f, "Network unreachable"),
            Reply::OtherReply(u)           => write!(f, "Other reply ({})", u),
            Reply::TtlExpired              => write!(f, "TTL expired"),
        }
    }
}

/// SOCKS5 protocol error
#[derive(Clone)]
pub struct Error {
    /// Reply code
    pub reply: Reply,
    /// Error message
    pub message: String,
}

impl Error {
    pub fn new<S>(reply: Reply, message: S) -> Error
    where
        S: Into<String>,
    {
        Error {
            reply,
            message: message.into(),
        }
    }
}

impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(Reply::GeneralFailure, err.to_string())
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, err.message)
    }
}

/// SOCKS5 address type
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}

impl Address {
    /// Parse from a `AsyncRead`
    pub async fn read_from<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
        match addr_type {
            consts::SOCKS5_ADDR_TYPE_IPV4 => {
                let mut buf = BytesMut::with_capacity(6);
                buf.resize(6, 0);
                let _ = stream.read_exact(&mut buf).await?;

                let mut cursor = buf.to_bytes();
                let v4addr = Ipv4Addr::new(cursor.get_u8(), cursor.get_u8(), cursor.get_u8(), cursor.get_u8());
                let port = cursor.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port))))
            }
            consts::SOCKS5_ADDR_TYPE_IPV6 => {
                let mut buf = [0u8; 18];
                let _ = stream.read_exact(&mut buf).await?;

                let mut cursor = Cursor::new(&buf);
                let v6addr = Ipv6Addr::new(
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                );
                let port = cursor.get_u16();

                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }
            consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let _ = stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                let buf_length = length + 2;
                let mut buf = BytesMut::with_capacity(buf_length);
                buf.resize(buf_length, 0);
                let _ = stream.read_exact(&mut buf).await?;

                let mut cursor = buf.to_bytes();
                let mut raw_addr = Vec::with_capacity(length);
                raw_addr.put(&mut BufExt::take(&mut cursor, length));
                let addr = match String::from_utf8(raw_addr) {
                    Ok(addr) => addr,
                    Err(..) => return Err(Error::new(Reply::GeneralFailure, "invalid address encoding")),
                };
                let port = cursor.get_u16();

                Ok(Address::DomainNameAddress(addr, port))
            }
            _ => {
                // Wrong Address Type . Socks5 only supports ipv4, ipv6 and domain name
                Err(Error::new(
                    Reply::AddressTypeNotSupported,
                    format!("not supported address type {:#x}", addr_type),
                ))
            }
        }
    }

    /// Writes to writer
    #[inline]
    pub async fn write_to<W>(&self, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        writer.write_all(&buf).await
    }

    /// Writes to buffer
    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        write_address(self, buf)
    }

    /// Get required buffer size for serializing
    #[inline]
    pub fn serialized_len(&self) -> usize {
        get_addr_len(self)
    }

    /// Get associated port number
    pub fn port(&self) -> u16 {
        match *self {
            Address::SocketAddress(addr) => addr.port(),
            Address::DomainNameAddress(.., port) => port,
        }
    }
}

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<vec::IntoIter<SocketAddr>> {
        match self.clone() {
            Address::SocketAddress(addr) => Ok(vec![addr].into_iter()),
            Address::DomainNameAddress(addr, port) => (&addr[..], port).to_socket_addrs(),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}

impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Address {
        Address::DomainNameAddress(dn, port)
    }
}

impl From<&Address> for Address {
    fn from(addr: &Address) -> Address {
        addr.clone()
    }
}

/// Parse `Address` error
#[derive(Debug)]
pub struct AddressError;

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Address, AddressError> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(Address::SocketAddress(addr)),
            Err(..) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => match port.parse::<u16>() {
                        Ok(port) => Ok(Address::DomainNameAddress(dn.to_owned(), port)),
                        Err(..) => Err(AddressError),
                    },
                    (Some(dn), None) => {
                        // Assume it is 80 (http's default port)
                        Ok(Address::DomainNameAddress(dn.to_owned(), 80))
                    }
                    _ => Err(AddressError),
                }
            }
        }
    }
}

fn write_ipv4_address<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV4); // Address type
    buf.put_slice(&addr.ip().octets()); // Ipv4 bytes
    buf.put_u16(addr.port()); // Port
}

fn write_ipv6_address<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV6); // Address type
    for seg in &addr.ip().segments() {
        buf.put_u16(*seg); // Ipv6 bytes
    }
    buf.put_u16(addr.port()); // Port
}

fn write_domain_name_address<B: BufMut>(dnaddr: &str, port: u16, buf: &mut B) {
    assert!(dnaddr.len() <= u8::max_value() as usize);

    buf.put_u8(consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME);
    buf.put_u8(dnaddr.len() as u8);
    buf.put_slice(dnaddr[..].as_bytes());
    buf.put_u16(port);
}

fn write_socket_address<B: BufMut>(addr: &SocketAddr, buf: &mut B) {
    match *addr {
        SocketAddr::V4(ref addr) => write_ipv4_address(addr, buf),
        SocketAddr::V6(ref addr) => write_ipv6_address(addr, buf),
    }
}

fn write_address<B: BufMut>(addr: &Address, buf: &mut B) {
    match *addr {
        Address::SocketAddress(ref addr) => write_socket_address(addr, buf),
        Address::DomainNameAddress(ref dnaddr, ref port) => write_domain_name_address(dnaddr, *port, buf),
    }
}

#[inline]
fn get_addr_len(atyp: &Address) -> usize {
    match *atyp {
        Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
        Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
        Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
    }
}

/// TCP request header after handshake
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct TcpRequestHeader {
    /// SOCKS5 command
    pub command: Command,
    /// Remote address
    pub address: Address,
}

impl TcpRequestHeader {
    /// Creates a request header
    pub fn new(cmd: Command, addr: Address) -> TcpRequestHeader {
        TcpRequestHeader {
            command: cmd,
            address: addr,
        }
    }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<TcpRequestHeader, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != consts::SOCKS5_VERSION {
            return Err(Error::new(
                Reply::ConnectionRefused,
                format!("unsupported socks version {:#x}", ver),
            ));
        }

        let cmd = buf[1];
        let command = match Command::from_u8(cmd) {
            Some(c) => c,
            None => {
                return Err(Error::new(
                    Reply::CommandNotSupported,
                    format!("unsupported command {:#x}", cmd),
                ));
            }
        };

        let address = Address::read_from(r).await?;
        Ok(TcpRequestHeader { command, address })
    }

    /// Write data into a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Writes to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpRequestHeader {
            ref address,
            ref command,
        } = *self;

        buf.put_slice(&[consts::SOCKS5_VERSION, command.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

/// TCP response header
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct TcpResponseHeader {
    /// SOCKS5 reply
    pub reply: Reply,
    /// Reply address
    pub address: Address,
}

impl TcpResponseHeader {
    /// Creates a response header
    pub fn new(reply: Reply, address: Address) -> TcpResponseHeader {
        TcpResponseHeader { reply, address }
    }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<TcpResponseHeader, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let reply_code = buf[1];

        if ver != consts::SOCKS5_VERSION {
            return Err(Error::new(
                Reply::ConnectionRefused,
                format!("unsupported socks version {:#x}", ver),
            ));
        }

        let address = Address::read_from(r).await?;

        Ok(TcpResponseHeader {
            reply: Reply::from_u8(reply_code),
            address,
        })
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Writes to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpResponseHeader { ref reply, ref address } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, reply.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}

/// SOCKS5 handshake request packet
///
/// ```plain
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 5  |    1     | 1 to 255 |
/// +----+----------+----------|
/// ```
#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}

impl HandshakeRequest {
    /// Creates a handshake request
    pub fn new(methods: Vec<u8>) -> HandshakeRequest {
        HandshakeRequest { methods }
    }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> io::Result<HandshakeRequest>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let nmet = buf[1];

        if ver != consts::SOCKS5_VERSION {
            use std::io::{Error, ErrorKind};
            let err = Error::new(ErrorKind::InvalidData, format!("unsupported socks version {:#x}", ver));
            return Err(err);
        }

        let mut methods = vec![0u8; nmet as usize];
        let _ = r.read_exact(&mut methods).await?;

        Ok(HandshakeRequest { methods })
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let HandshakeRequest { ref methods } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, methods.len() as u8]);
        buf.put_slice(&methods);
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        2 + self.methods.len()
    }
}

/// SOCKS5 handshake response packet
///
/// ```plain
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
#[derive(Clone, Debug, Copy)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}

impl HandshakeResponse {
    /// Creates a handshake response
    pub fn new(cm: u8) -> HandshakeResponse {
        HandshakeResponse { chosen_method: cm }
    }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> io::Result<HandshakeResponse>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let met = buf[1];

        if ver != consts::SOCKS5_VERSION {
            use std::io::{Error, ErrorKind};
            let err = Error::new(ErrorKind::InvalidData, format!("unsupported socks version {:#x}", ver));
            Err(err)
        } else {
            Ok(HandshakeResponse { chosen_method: met })
        }
    }

    /// Write to a writer
    pub async fn write_to<W>(self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(self, buf: &mut B) {
        buf.put_slice(&[consts::SOCKS5_VERSION, self.chosen_method]);
    }

    /// Length in bytes
    pub fn serialized_len(self) -> usize {
        2
    }
}

/// UDP ASSOCIATE request header
///
/// ```plain
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
#[derive(Clone, Debug)]
pub struct UdpAssociateHeader {
    /// Fragment
    ///
    /// ShadowSocks does not support fragment, so this frag must be 0x00
    pub frag: u8,
    /// Remote address
    pub address: Address,
}

impl UdpAssociateHeader {
    /// Creates a header
    pub fn new(frag: u8, address: Address) -> UdpAssociateHeader {
        UdpAssociateHeader { frag, address }
    }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<UdpAssociateHeader, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;

        let frag = buf[2];
        let address = Address::read_from(r).await?;
        Ok(UdpAssociateHeader::new(frag, address))
    }

    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let UdpAssociateHeader { ref frag, ref address } = *self;
        buf.put_slice(&[0x00, 0x00, *frag]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        3 + self.address.serialized_len()
    }
}
