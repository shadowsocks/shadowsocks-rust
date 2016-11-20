// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG <zonyitoo@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! Socks5 protocol definition (RFC1928)
//!
//! Implements [SOCKS Protocol Version 5](https://www.ietf.org/rfc/rfc1928.txt) proxy protocol

#![allow(dead_code)]

use std::fmt::{self, Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Cursor, Read, Write};
use std::vec;
use std::error;
use std::convert::From;

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use futures::{self, Future};

use tokio_core::io::{read_exact, write_all};

use relay::BoxIoFuture;

const SOCKS5_VERSION: u8 = 0x05;

pub const SOCKS5_AUTH_METHOD_NONE: u8 = 0x00;
pub const SOCKS5_AUTH_METHOD_GSSAPI: u8 = 0x01;
pub const SOCKS5_AUTH_METHOD_PASSWORD: u8 = 0x02;
pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE: u8 = 0xff;

const SOCKS5_CMD_TCP_CONNECT: u8 = 0x01;
const SOCKS5_CMD_TCP_BIND: u8 = 0x02;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

const SOCKS5_ADDR_TYPE_IPV4: u8 = 0x01;
const SOCKS5_ADDR_TYPE_DOMAIN_NAME: u8 = 0x03;
const SOCKS5_ADDR_TYPE_IPV6: u8 = 0x04;

const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
const SOCKS5_REPLY_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;
const SOCKS5_REPLY_TTL_EXPIRED: u8 = 0x06;
const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

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
    fn as_u8(&self) -> u8 {
        match *self {
            Command::TcpConnect => SOCKS5_CMD_TCP_CONNECT,
            Command::TcpBind => SOCKS5_CMD_TCP_BIND,
            Command::UdpAssociate => SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> Option<Command> {
        match code {
            SOCKS5_CMD_TCP_CONNECT => Some(Command::TcpConnect),
            SOCKS5_CMD_TCP_BIND => Some(Command::TcpBind),
            SOCKS5_CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
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
    fn as_u8(&self) -> u8 {
        match *self {
            Reply::Succeeded => SOCKS5_REPLY_SUCCEEDED,
            Reply::GeneralFailure => SOCKS5_REPLY_GENERAL_FAILURE,
            Reply::ConnectionNotAllowed => SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            Reply::NetworkUnreachable => SOCKS5_REPLY_NETWORK_UNREACHABLE,
            Reply::HostUnreachable => SOCKS5_REPLY_HOST_UNREACHABLE,
            Reply::ConnectionRefused => SOCKS5_REPLY_CONNECTION_REFUSED,
            Reply::TtlExpired => SOCKS5_REPLY_TTL_EXPIRED,
            Reply::CommandNotSupported => SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            Reply::AddressTypeNotSupported => SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            Reply::OtherReply(c) => c,
        }
    }

    #[inline]
    fn from_u8(code: u8) -> Reply {
        match code {
            SOCKS5_REPLY_SUCCEEDED => Reply::Succeeded,
            SOCKS5_REPLY_GENERAL_FAILURE => Reply::GeneralFailure,
            SOCKS5_REPLY_CONNECTION_NOT_ALLOWED => Reply::ConnectionNotAllowed,
            SOCKS5_REPLY_NETWORK_UNREACHABLE => Reply::NetworkUnreachable,
            SOCKS5_REPLY_HOST_UNREACHABLE => Reply::HostUnreachable,
            SOCKS5_REPLY_CONNECTION_REFUSED => Reply::ConnectionRefused,
            SOCKS5_REPLY_TTL_EXPIRED => Reply::TtlExpired,
            SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => Reply::CommandNotSupported,
            SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Reply::AddressTypeNotSupported,
            _ => Reply::OtherReply(code),
        }
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Reply::Succeeded => write!(f, "Succeeded"),
            Reply::AddressTypeNotSupported => write!(f, "Address type not supported"),
            Reply::CommandNotSupported => write!(f, "Command not supported"),
            Reply::ConnectionNotAllowed => write!(f, "Connection not allowed"),
            Reply::ConnectionRefused => write!(f, "Connection refused"),
            Reply::GeneralFailure => write!(f, "General failure"),
            Reply::HostUnreachable => write!(f, "Host unreachable"),
            Reply::NetworkUnreachable => write!(f, "Network unreachable"),
            Reply::OtherReply(u) => write!(f, "Other reply ({})", u),
            Reply::TtlExpired => write!(f, "TTL expired"),
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
        Error {
            reply: reply,
            message: message.to_string(),
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
        Error::new(Reply::GeneralFailure,
                   <io::Error as error::Error>::description(&err))
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
    pub fn read_from<R: Read + 'static>(stream: R) -> Box<Future<Item = (R, Address), Error = Error>> {
        parse_request_header(stream)
    }

    #[inline]
    pub fn write_to<W: Write + 'static>(self, writer: W) -> BoxIoFuture<W> {
        write_addr(self, writer)
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

/// TCP request header after handshake
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
    pub fn read_from<R: Read + 'static>(r: R) -> Box<Future<Item = (R, TcpRequestHeader), Error = Error>> {
        let fut = read_exact(r, [0u8; 3])
            .map_err(From::from)
            .and_then(|(r, buf)| {
                let ver = buf[0];
                if ver != SOCKS5_VERSION {
                    return Err(Error::new(Reply::ConnectionRefused, "Unsupported Socks version"));
                }

                let cmd = buf[1];
                let command = match Command::from_u8(cmd) {
                    Some(c) => c,
                    None => return Err(Error::new(Reply::CommandNotSupported, "Unsupported command")),
                };

                Ok((r, command))
            })
            .and_then(|(r, command)| {
                Address::read_from(r).map(move |(conn, address)| {
                    let header = TcpRequestHeader {
                        command: command,
                        address: address,
                    };

                    (conn, header)
                })
            });

        Box::new(fut)
    }

    /// Write data into a writer
    pub fn write_to<W: Write + 'static>(self, w: W) -> BoxIoFuture<W> {
        let mut buf = Vec::with_capacity(self.len());
        let TcpRequestHeader { address, command } = self;
        let fut = futures::lazy(move || {
                buf.write_all(&[SOCKS5_VERSION, command.as_u8(), 0x00])?;
                Ok(buf)
            })
            .and_then(|buf| address.write_to(buf))
            .and_then(|buf| write_all(w, buf))
            .map(|(w, _)| w);

        Box::new(fut)
    }

    /// Length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.address.len() + 3
    }
}

/// TCP response header
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
        TcpResponseHeader {
            reply: reply,
            address: address,
        }
    }

    /// Read from a reader
    pub fn read_from<R: Read + 'static>(r: R) -> Box<Future<Item = (R, TcpResponseHeader), Error = Error>> {
        let fut = read_exact(r, [0u8; 3])
            .map_err(From::from)
            .and_then(|(r, buf)| {
                let ver = buf[0];
                let reply_code = buf[1];

                if ver != SOCKS5_VERSION {
                    return Err(Error::new(Reply::ConnectionRefused, "Unsupported Socks version"));
                }

                Ok((r, reply_code))
            })
            .and_then(|(r, reply_code)| {
                Address::read_from(r).map(move |(r, address)| {
                    let rep = TcpResponseHeader {
                        reply: Reply::from_u8(reply_code),
                        address: address,
                    };

                    (r, rep)
                })
            });

        Box::new(fut)
    }

    /// Write to a writer
    pub fn write_to<W: Write + 'static>(self, w: W) -> BoxIoFuture<W> {
        let mut buf = Vec::with_capacity(self.len());
        let TcpResponseHeader { reply, address } = self;
        let fut = futures::lazy(move || {
                buf.write_all(&[SOCKS5_VERSION, reply.as_u8(), 0x00])?;
                Ok(buf)
            })
            .and_then(|buf| address.write_to(buf))
            .and_then(|buf| write_all(w, buf))
            .map(|(w, _)| w);

        Box::new(fut)
    }

    /// Length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.address.len() + 3
    }
}

fn parse_request_header<R: Read + 'static>(stream: R) -> Box<Future<Item = (R, Address), Error = Error>> {
    let fut = read_exact(stream, [0u8])
        .map_err(|_| Error::new(Reply::GeneralFailure, "Error while reading address type"))
        .and_then(|(conn, atyp)| {
            match atyp[0] {
                SOCKS5_ADDR_TYPE_IPV4 => {
                    let v4addr = read_exact(conn, [0u8; 6]).map_err(From::from);
                    let fut = v4addr.and_then(|(conn, v4addr)| {
                        let mut stream = Cursor::new(v4addr);
                        let v4addr = Ipv4Addr::new(stream.read_u8()?,
                                                   stream.read_u8()?,
                                                   stream.read_u8()?,
                                                   stream.read_u8()?);
                        let port = stream.read_u16::<BigEndian>()?;

                        Ok((conn, Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port)))))
                    });
                    Box::new(fut) as Box<Future<Item = (R, Address), Error = Error>>
                }
                SOCKS5_ADDR_TYPE_IPV6 => {
                    let v6addr = read_exact(conn, [0u8; 18]).map_err(From::from);
                    let fut = v6addr.and_then(|(conn, v6addr)| {
                        let mut stream = Cursor::new(v6addr);
                        let v6addr = Ipv6Addr::new(stream.read_u16::<BigEndian>()?,
                                                   stream.read_u16::<BigEndian>()?,
                                                   stream.read_u16::<BigEndian>()?,
                                                   stream.read_u16::<BigEndian>()?,
                                                   stream.read_u16::<BigEndian>()?,
                                                   stream.read_u16::<BigEndian>()?,
                                                   stream.read_u16::<BigEndian>()?,
                                                   stream.read_u16::<BigEndian>()?);
                        let port = stream.read_u16::<BigEndian>()?;

                        Ok((conn, Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(v6addr, port, 0, 0)))))
                    });
                    Box::new(fut) as Box<Future<Item = (R, Address), Error = Error>>
                }
                SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                    let addr_len = read_exact(conn, [0u8]).map_err(From::from);
                    let fut = addr_len.and_then(|(conn, addr_len)| {
                        let addr_len = addr_len[0] as usize;
                        let raw_addr = read_exact(conn, vec![0u8; addr_len]).map_err(From::from);
                        raw_addr.and_then(|(conn, raw_addr)| {
                            let port = read_exact(conn, [0u8; 2]).map_err(From::from);
                            port.and_then(|(conn, port)| {
                                let mut stream = Cursor::new(port);
                                let port = try!(stream.read_u16::<BigEndian>());

                                let addr = match String::from_utf8(raw_addr) {
                                    Ok(addr) => addr,
                                    Err(..) => {
                                        return Err(Error::new(Reply::GeneralFailure, "Invalid address encoding"))
                                    }
                                };

                                Ok((conn, Address::DomainNameAddress(addr, port)))
                            })
                        })
                    });
                    Box::new(fut) as Box<Future<Item = (R, Address), Error = Error>>
                }
                _ => {
                    // Address type not supported
                    let fut = futures::failed(Error::new(Reply::AddressTypeNotSupported, "Not supported address type"));
                    Box::new(fut) as Box<Future<Item = (R, Address), Error = Error>>
                }
            }
        });

    Box::new(fut)
}

fn write_addr<W: Write + 'static>(addr: Address, w: W) -> BoxIoFuture<W> {
    match addr {
        Address::SocketAddress(addr) => {
            match addr {
                SocketAddr::V4(addr) => {
                    let fut = futures::lazy(move || {
                            let mut buf = [0u8; 1 + 4 + 2];
                            {
                                let mut cur = Cursor::new(&mut buf[..]);
                                cur.write_u8(SOCKS5_ADDR_TYPE_IPV4)?; // Address type
                                cur.write_all(&addr.ip().octets())?; // Ipv4 bytes
                                cur.write_u16::<BigEndian>(addr.port())?;
                            }

                            Ok(buf)
                        })
                        .and_then(|buf| write_all(w, buf))
                        .map(|(conn, _)| conn);
                    Box::new(fut) as BoxIoFuture<W>
                }
                SocketAddr::V6(addr) => {
                    let fut = futures::lazy(move || {
                            let mut buf = [0u8; 1 + 16 + 2];

                            {
                                let mut cur = Cursor::new(&mut buf[..]);
                                cur.write_u8(SOCKS5_ADDR_TYPE_IPV6)?;
                                for seg in &addr.ip().segments() {
                                    cur.write_u16::<BigEndian>(*seg)?;
                                }
                                cur.write_u16::<BigEndian>(addr.port())?;
                            }

                            Ok(buf)
                        })
                        .and_then(|rbuf| write_all(w, rbuf))
                        .map(|(conn, _)| conn);
                    Box::new(fut) as BoxIoFuture<W>
                }
            }
        }
        Address::DomainNameAddress(dnaddr, port) => {
            let fut = futures::lazy(move || {
                    let mut buf = Vec::with_capacity(1 + 1 + dnaddr.len() + 2);
                    buf.write_u8(SOCKS5_ADDR_TYPE_DOMAIN_NAME)?;
                    buf.write_u8(dnaddr.len() as u8)?;
                    buf.write_all(dnaddr[..].as_bytes())?;
                    buf.write_u16::<BigEndian>(port)?;
                    Ok(buf)
                })
                .and_then(|buf| write_all(w, buf))
                .map(|(conn, _)| conn);
            Box::new(fut) as BoxIoFuture<W>
        }
    }
}

#[inline]
fn get_addr_len(atyp: &Address) -> usize {
    match atyp {
        &Address::SocketAddress(addr) => {
            match addr {
                SocketAddr::V4(..) => 1 + 4 + 2,
                SocketAddr::V6(..) => 1 + 8 * 2 + 2,
            }
        }
        &Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
    }
}

/// SOCKS5 handshake request packet
///
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 5  |    1     | 1 to 255 |
/// +----+----------+----------|
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
    pub fn read_from<R: Read + 'static>(r: R) -> BoxIoFuture<(R, HandshakeRequest)> {
        let fut = read_exact(r, [0u8, 0u8])
            .and_then(|(r, buf)| {
                let ver = buf[0];
                let nmet = buf[1];

                if ver != SOCKS5_VERSION {
                    return Err(io::Error::new(io::ErrorKind::Other, "Invalid Socks5 version"));
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
    pub fn write_to<W: Write + 'static>(self, w: W) -> BoxIoFuture<W> {
        let mut buf = Vec::with_capacity(2 + self.methods.len());
        let HandshakeRequest { methods } = self;
        let fut = futures::lazy(move || {
                buf.write_all(&[SOCKS5_VERSION, methods.len() as u8])?;
                buf.write_all(&methods[..])?;
                Ok(buf)
            })
            .and_then(|buf| write_all(w, buf))
            .map(|(w, _)| w);

        Box::new(fut)
    }
}

/// SOCKS5 handshake response packet
///
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
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
    pub fn read_from<R: Read + 'static>(r: R) -> BoxIoFuture<(R, HandshakeResponse)> {
        let fut = read_exact(r, [0u8, 0u8]).and_then(|(r, buf)| {
            let ver = buf[0];
            let met = buf[1];

            if ver != SOCKS5_VERSION {
                Err(io::Error::new(io::ErrorKind::Other, "Invalid Socks5 version"))
            } else {
                Ok((r, HandshakeResponse { chosen_method: met }))
            }
        });
        Box::new(fut)
    }

    /// Write to a writer
    pub fn write_to<W: Write + 'static>(self, w: W) -> BoxIoFuture<W> {
        Box::new(write_all(w, [SOCKS5_VERSION, self.chosen_method]).map(|(w, _)| w))
    }
}

/// UDP ASSOCIATE request header
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
        UdpAssociateHeader {
            frag: frag,
            address: address,
        }
    }

    /// Read from a reader
    pub fn read_from<R: Read + 'static>(r: R) -> Box<Future<Item = (R, UdpAssociateHeader), Error = Error>> {
        let fut = read_exact(r, [0u8; 3])
            .map_err(From::from)
            .and_then(|(r, buf)| {
                let frag = buf[2];
                Address::read_from(r).map(move |(r, address)| {
                    let h = UdpAssociateHeader::new(frag, address);
                    (r, h)
                })
            });
        Box::new(fut)
    }

    /// Write to a writer
    pub fn write_to<W: Write + 'static>(self, w: W) -> BoxIoFuture<W> {
        let mut buf = Vec::with_capacity(self.len());
        let UdpAssociateHeader { frag, address } = self;
        let fut = futures::lazy(move || {
                buf.write_all(&[0x00, 0x00, frag])?;
                Ok(buf)
            })
            .and_then(|buf| address.write_to(buf))
            .and_then(|buf| write_all(w, buf))
            .map(|(w, _)| w);
        Box::new(fut)
    }

    /// Length in bytes
    #[inline]
    pub fn len(&self) -> usize {
        3 + self.address.len()
    }
}
