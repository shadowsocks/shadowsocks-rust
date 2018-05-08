//! Socks5 protocol definition (RFC1928)
//!
//! Implements [SOCKS Protocol Version 5](https://www.ietf.org/rfc/rfc1928.txt) proxy protocol

use std::convert::From;
use std::error;
use std::fmt::{self, Debug, Formatter};
use std::io::{self, Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::u8;
use std::vec;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, Bytes, BytesMut, IntoBuf};

use futures::{Async, Future, Poll};

use tokio_io::io::read_exact;
use tokio_io::{AsyncRead, AsyncWrite, IoFuture};

pub use self::consts::{
    SOCKS5_AUTH_METHOD_GSSAPI, SOCKS5_AUTH_METHOD_NONE, SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE, SOCKS5_AUTH_METHOD_PASSWORD,
};

use super::utils::{write_bytes, WriteBytes};

#[cfg_attr(rustfmt, rustfmt_skip)]
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
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn as_u8(&self) -> u8 {
        match *self {
            Command::TcpConnect   => consts::SOCKS5_CMD_TCP_CONNECT,
            Command::TcpBind      => consts::SOCKS5_CMD_TCP_BIND,
            Command::UdpAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    #[cfg_attr(rustfmt, rustfmt_skip)]
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
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn as_u8(&self) -> u8 {
        match *self {
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
    #[cfg_attr(rustfmt, rustfmt_skip)]
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
    #[cfg_attr(rustfmt, rustfmt_skip)]
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
    pub fn new(reply: Reply, message: &str) -> Error {
        Error { reply: reply,
                message: message.to_string(), }
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

impl error::Error for Error {
    fn description(&self) -> &str {
        &self.message[..]
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(Reply::GeneralFailure, <io::Error as error::Error>::description(&err))
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
    #[inline]
    pub fn read_from<R: AsyncRead>(stream: R) -> ReadAddress<R> {
        ReadAddress::new(stream)
    }

    /// Writes to writer
    #[inline]
    pub fn write_to<W: AsyncWrite>(self, writer: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        write_bytes(writer, buf.freeze())
    }

    /// Writes to buffer
    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        write_address(self, buf)
    }

    #[inline]
    pub fn len(&self) -> usize {
        get_addr_len(self)
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

pub struct ReadAddress<R>
    where R: AsyncRead
{
    reader: Option<R>,
    state: ReadAddressState,
    buf: Option<BytesMut>,
    already_read: usize,
}

enum ReadAddressState {
    ReadingType,
    ReadingIpv4,
    ReadingIpv6,
    ReadingDomainNameLength,
    ReadingDomainName,
}

impl<R> Future for ReadAddress<R>
    where R: AsyncRead
{
    type Item = (R, Address);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        debug_assert!(self.reader.is_some());

        loop {
            match self.state {
                ReadAddressState::ReadingType => {
                    try_ready!(self.read_addr_type());
                }
                ReadAddressState::ReadingIpv4 => {
                    let addr = try_ready!(self.read_ipv4());
                    let reader = self.reader.take().unwrap();
                    return Ok((reader, addr).into());
                }
                ReadAddressState::ReadingIpv6 => {
                    let addr = try_ready!(self.read_ipv6());
                    let reader = self.reader.take().unwrap();
                    return Ok((reader, addr).into());
                }
                ReadAddressState::ReadingDomainNameLength => {
                    try_ready!(self.read_domain_name_length());
                }
                ReadAddressState::ReadingDomainName => {
                    let addr = try_ready!(self.read_domain_name());
                    let reader = self.reader.take().unwrap();
                    return Ok((reader, addr).into());
                }
            };
        }
    }
}

impl<R> ReadAddress<R>
    where R: AsyncRead
{
    fn new(r: R) -> ReadAddress<R> {
        ReadAddress { reader: Some(r),
                      state: ReadAddressState::ReadingType,
                      buf: None,
                      already_read: 0, }
    }

    fn read_addr_type(&mut self) -> Poll<(), Error> {
        let addr_type = try_nb!(self.reader.as_mut().unwrap().read_u8());
        match addr_type {
            consts::SOCKS5_ADDR_TYPE_IPV4 => {
                self.state = ReadAddressState::ReadingIpv4;
                self.alloc_buf(6);
            }
            consts::SOCKS5_ADDR_TYPE_IPV6 => {
                self.state = ReadAddressState::ReadingIpv6;
                self.alloc_buf(18);
            }
            consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                self.state = ReadAddressState::ReadingDomainNameLength;
            }
            _ => {
                error!("Invalid address type {}", addr_type);
                return Err(Error::new(Reply::AddressTypeNotSupported, "Not supported address type"));
            }
        };

        Ok(Async::Ready(()))
    }

    fn read_ipv4(&mut self) -> Poll<Address, Error> {
        try_ready!(self.read_data());
        let mut stream: Cursor<Bytes> = self.freeze_buf().into_buf();
        let v4addr = Ipv4Addr::new(stream.read_u8()?,
                                   stream.read_u8()?,
                                   stream.read_u8()?,
                                   stream.read_u8()?);
        let port = stream.read_u16::<BigEndian>()?;
        let addr = Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port)));
        Ok(Async::Ready(addr))
    }

    fn read_ipv6(&mut self) -> Poll<Address, Error> {
        try_ready!(self.read_data());
        let mut stream: Cursor<Bytes> = self.freeze_buf().into_buf();
        let v6addr = Ipv6Addr::new(stream.read_u16::<BigEndian>()?,
                                   stream.read_u16::<BigEndian>()?,
                                   stream.read_u16::<BigEndian>()?,
                                   stream.read_u16::<BigEndian>()?,
                                   stream.read_u16::<BigEndian>()?,
                                   stream.read_u16::<BigEndian>()?,
                                   stream.read_u16::<BigEndian>()?,
                                   stream.read_u16::<BigEndian>()?);
        let port = stream.read_u16::<BigEndian>()?;

        let addr = Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(v6addr, port, 0, 0)));
        Ok(Async::Ready(addr))
    }

    fn read_domain_name_length(&mut self) -> Poll<(), Error> {
        let length = try_nb!(self.reader.as_mut().unwrap().read_u8());
        self.state = ReadAddressState::ReadingDomainName;
        self.alloc_buf(length as usize + 2);
        Ok(Async::Ready(()))
    }

    fn read_domain_name(&mut self) -> Poll<Address, Error> {
        try_ready!(self.read_data());
        let buf = self.freeze_buf();
        let addr_len = buf.len() - 2;
        let mut stream: Cursor<Bytes> = buf.into_buf();

        let mut raw_addr = Vec::with_capacity(addr_len);
        unsafe {
            raw_addr.set_len(addr_len);
        }
        stream.read_exact(&mut raw_addr)?;

        let addr = match String::from_utf8(raw_addr) {
            Ok(addr) => addr,
            Err(..) => return Err(Error::new(Reply::GeneralFailure, "Invalid address encoding")),
        };
        let port = stream.read_u16::<BigEndian>()?;

        let addr = Address::DomainNameAddress(addr, port);
        Ok(Async::Ready(addr))
    }

    fn alloc_buf(&mut self, size: usize) {
        let mut buf = BytesMut::with_capacity(size);
        unsafe {
            buf.set_len(size);
        }
        self.buf = Some(buf);
    }

    fn read_data(&mut self) -> Poll<(), io::Error> {
        let buf = self.buf.as_mut().unwrap();

        while self.already_read < buf.len() {
            match self.reader.as_mut().unwrap().read(&mut buf[self.already_read..]) {
                Ok(0) => {
                    let err = io::Error::new(io::ErrorKind::Other, "Unexpected EOF");
                    return Err(err);
                }
                Ok(n) => self.already_read += n,
                Err(err) => return Err(err),
            }
        }

        Ok(Async::Ready(()))
    }

    fn freeze_buf(&mut self) -> Bytes {
        let buf = self.buf.take().unwrap();
        buf.freeze()
    }
}

fn write_ipv4_address<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    let mut dbuf = [0u8; 1 + 4 + 2];
    {
        let mut cur = Cursor::new(&mut dbuf[..]);
        let _ = cur.write_u8(consts::SOCKS5_ADDR_TYPE_IPV4); // Address type
        let _ = cur.write_all(&addr.ip().octets()); // Ipv4 bytes
        let _ = cur.write_u16::<BigEndian>(addr.port());
    }
    buf.put_slice(&dbuf[..]);
}

fn write_ipv6_address<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    let mut dbuf = [0u8; 1 + 16 + 2];

    {
        let mut cur = Cursor::new(&mut dbuf[..]);
        let _ = cur.write_u8(consts::SOCKS5_ADDR_TYPE_IPV6);
        for seg in &addr.ip().segments() {
            let _ = cur.write_u16::<BigEndian>(*seg);
        }
        let _ = cur.write_u16::<BigEndian>(addr.port());
    }

    buf.put_slice(&dbuf[..]);
}

fn write_domain_name_address<B: BufMut>(dnaddr: &str, port: u16, buf: &mut B) {
    assert!(dnaddr.len() <= u8::max_value() as usize);

    buf.put_u8(consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME);
    buf.put_u8(dnaddr.len() as u8);
    buf.put_slice(dnaddr[..].as_bytes());
    buf.put_u16_be(port);
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
        TcpRequestHeader { command: cmd,
                           address: addr, }
    }

    /// Read from a reader
    pub fn read_from<R: AsyncRead + Send + 'static>(
        r: R)
        -> Box<Future<Item = (R, TcpRequestHeader), Error = Error> + Send + 'static> {
        let fut = read_exact(r, [0u8; 3]).map_err(From::from)
                                         .and_then(|(r, buf)| {
                                                       let ver = buf[0];
                                                       if ver != consts::SOCKS5_VERSION {
                                                           return Err(Error::new(Reply::ConnectionRefused,
                                                                                 "Unsupported Socks version"));
                                                       }

                                                       let cmd = buf[1];
                                                       let command = match Command::from_u8(cmd) {
                                                           Some(c) => c,
                                                           None => {
                                                               return Err(Error::new(Reply::CommandNotSupported,
                                                                                     "Unsupported command"))
                                                           }
                                                       };

                                                       Ok((r, command))
                                                   })
                                         .and_then(|(r, command)| {
                                                       Address::read_from(r).map(move |(conn, address)| {
                                                           let header = TcpRequestHeader { command: command,
                                                                                           address: address, };

                                                           (conn, header)
                                                       })
                                                   });

        Box::new(fut)
    }

    /// Write data into a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Writes to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpRequestHeader { ref address,
                               ref command, } = *self;

        buf.put_slice(&[consts::SOCKS5_VERSION, command.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.address.len() + 3
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
        TcpResponseHeader { reply: reply,
                            address: address, }
    }

    /// Read from a reader
    pub fn read_from<R: AsyncRead + Send + 'static>(
        r: R)
        -> Box<Future<Item = (R, TcpResponseHeader), Error = Error> + Send + 'static> {
        let fut = read_exact(r, [0u8; 3]).map_err(From::from)
                                         .and_then(|(r, buf)| {
                                                       let ver = buf[0];
                                                       let reply_code = buf[1];

                                                       if ver != consts::SOCKS5_VERSION {
                                                           return Err(Error::new(Reply::ConnectionRefused,
                                                                                 "Unsupported Socks version"));
                                                       }

                                                       Ok((r, reply_code))
                                                   })
                                         .and_then(|(r, reply_code)| {
                                                       Address::read_from(r).map(move |(r, address)| {
                                                           let rep = TcpResponseHeader { reply:
                                                                                             Reply::from_u8(reply_code),
                                                                                         address: address, };

                                                           (r, rep)
                                                       })
                                                   });

        Box::new(fut)
    }

    /// Write to a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Writes to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpResponseHeader { ref reply, ref address } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, reply.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.address.len() + 3
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
        HandshakeRequest { methods: methods }
    }

    /// Read from a reader
    pub fn read_from<R: AsyncRead + Send + 'static>(r: R) -> IoFuture<(R, HandshakeRequest)> {
        let fut = read_exact(r, [0u8, 0u8]).and_then(|(r, buf)| {
                                                         let ver = buf[0];
                                                         let nmet = buf[1];

                                                         if ver != consts::SOCKS5_VERSION {
                                                             return Err(io::Error::new(io::ErrorKind::Other,
                                                                                       "Invalid Socks5 version"));
                                                         }

                                                         Ok((r, nmet))
                                                     })
                                           .and_then(|(r, nmet)| {
                                               read_exact(r, vec![0u8; nmet as usize])
                              .and_then(|(r, methods)| Ok((r, HandshakeRequest { methods: methods })))
                                           });
        Box::new(fut)
    }

    /// Write to a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let HandshakeRequest { ref methods } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, methods.len() as u8]);
        buf.put_slice(&methods);
    }

    /// Get length of bytes
    pub fn len(&self) -> usize {
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
    pub fn read_from<R: AsyncRead + Send + 'static>(r: R) -> IoFuture<(R, HandshakeResponse)> {
        let fut = read_exact(r, [0u8, 0u8]).and_then(|(r, buf)| {
                                                         let ver = buf[0];
                                                         let met = buf[1];

                                                         if ver != consts::SOCKS5_VERSION {
                                                             Err(io::Error::new(io::ErrorKind::Other,
                                                                                "Invalid Socks5 version"))
                                                         } else {
                                                             Ok((r, HandshakeResponse { chosen_method: met }))
                                                         }
                                                     });
        Box::new(fut)
    }

    /// Write to a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&[consts::SOCKS5_VERSION, self.chosen_method]);
    }

    /// Length in bytes
    pub fn len(&self) -> usize {
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
        UdpAssociateHeader { frag: frag,
                             address: address, }
    }

    /// Read from a reader
    pub fn read_from<R: AsyncRead + Send + 'static>(
        r: R)
        -> Box<Future<Item = (R, UdpAssociateHeader), Error = Error> + Send + 'static> {
        let fut = read_exact(r, [0u8; 3]).map_err(From::from).and_then(|(r, buf)| {
            let frag = buf[2];
            Address::read_from(r).map(move |(r, address)| {
                                          let h = UdpAssociateHeader::new(frag, address);
                                          (r, h)
                                      })
        });
        Box::new(fut)
    }

    /// Write to a writer
    pub fn write_to<W: AsyncWrite>(self, w: W) -> WriteBytes<W, Bytes> {
        let mut buf = BytesMut::with_capacity(self.len());
        self.write_to_buf(&mut buf);
        write_bytes(w, buf.freeze())
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let UdpAssociateHeader { ref frag, ref address } = *self;
        buf.put_slice(&[0x00, 0x00, *frag]);
        address.write_to_buf(buf);
    }

    /// Length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        3 + self.address.len()
    }
}
