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

#![allow(dead_code)]

use std::fmt::{self, Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::{self, Read, Write};
use std::vec;
use std::error;
use std::convert::From;

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

const SOCKS5_VERSION : u8 = 0x05;

pub const SOCKS5_AUTH_METHOD_NONE            : u8 = 0x00;
pub const SOCKS5_AUTH_METHOD_GSSAPI          : u8 = 0x01;
pub const SOCKS5_AUTH_METHOD_PASSWORD        : u8 = 0x02;
pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE  : u8 = 0xff;

const SOCKS5_CMD_TCP_CONNECT   : u8 = 0x01;
const SOCKS5_CMD_TCP_BIND      : u8 = 0x02;
const SOCKS5_CMD_UDP_ASSOCIATE : u8 = 0x03;

const SOCKS5_ADDR_TYPE_IPV4        : u8 = 0x01;
const SOCKS5_ADDR_TYPE_DOMAIN_NAME : u8 = 0x03;
const SOCKS5_ADDR_TYPE_IPV6        : u8 = 0x04;

const SOCKS5_REPLY_SUCCEEDED                     : u8 = 0x00;
const SOCKS5_REPLY_GENERAL_FAILURE               : u8 = 0x01;
const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED        : u8 = 0x02;
const SOCKS5_REPLY_NETWORK_UNREACHABLE           : u8 = 0x03;
const SOCKS5_REPLY_HOST_UNREACHABLE              : u8 = 0x04;
const SOCKS5_REPLY_CONNECTION_REFUSED            : u8 = 0x05;
const SOCKS5_REPLY_TTL_EXPIRED                   : u8 = 0x06;
const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED         : u8 = 0x07;
const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED    : u8 = 0x08;

#[allow(dead_code)]
#[derive(Clone, Debug, Copy)]
pub enum Command {
    TcpConnect,
    TcpBind,
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

    OtherReply(u8)
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
            _ => Reply::OtherReply(code)
        }
    }
}

#[derive(Clone)]
pub struct Error {
    pub reply: Reply,
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
        Error::new(Reply::GeneralFailure, <io::Error as error::Error>::description(&err))
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainNameAddress(String, u16),
}

impl Address {
    #[inline]
    pub fn read_from<R: Read + Sized>(reader: &mut R) -> Result<Address, Error> {
        match parse_request_header(reader) {
            Ok((_, addr)) => Ok(addr),
            Err(err) => Err(err),
        }
    }

    #[inline]
    pub fn write_to<W: Write + Sized>(&self, writer: &mut W) -> io::Result<()> {
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

#[derive(Clone, Debug)]
pub struct TcpRequestHeader {
    pub command: Command,
    pub address: Address,
}

impl TcpRequestHeader {
    pub fn new(cmd: Command, addr: Address) -> TcpRequestHeader {
        TcpRequestHeader {
            command: cmd,
            address: addr,
        }
    }

    #[inline]
    pub fn read_from<R: Read>(stream: &mut R) -> Result<TcpRequestHeader, Error> {
        let ver = try!(stream.read_u8());
        if ver != SOCKS5_VERSION {
            return Err(Error::new(Reply::ConnectionRefused, "Unsupported Socks version"));
        }

        let cmd = try!(stream.read_u8());
        let _ = try!(stream.read_u8());

        Ok(TcpRequestHeader {
            command: match Command::from_u8(cmd) {
                Some(c) => c,
                None => return Err(Error::new(Reply::CommandNotSupported, "Unsupported command")),
            },
            address: try!(Address::read_from(stream)),
        })
    }

    #[inline]
    pub fn write_to<W: Write + Sized>(&self, stream: &mut W) -> io::Result<()> {
        try!(stream.write_all(&[SOCKS5_VERSION, self.command.as_u8(), 0x00]));
        try!(self.address.write_to(stream));

        Ok(())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.address.len() + 3
    }
}

#[derive(Clone, Debug)]
pub struct TcpResponseHeader {
    pub reply: Reply,
    pub address: Address,
}

impl TcpResponseHeader {
    pub fn new(reply: Reply, address: Address) -> TcpResponseHeader {
        TcpResponseHeader {
            reply: reply,
            address: address,
        }
    }

    #[inline]
    pub fn read_from<R: Read>(stream: &mut R) -> Result<TcpResponseHeader, Error> {
        let ver = try!(stream.read_u8());
        if ver != SOCKS5_VERSION {
            return Err(Error::new(Reply::ConnectionRefused, "Unsupported Socks version"));
        }

        let reply_code = try!(stream.read_u8());
        let _ = try!(stream.read_u8());

        Ok(TcpResponseHeader {
            reply: Reply::from_u8(reply_code),
            address: try!(Address::read_from(stream)),
        })
    }

    #[inline]
    pub fn write_to<W: Write + Sized>(&self, stream: &mut W) -> io::Result<()> {
        try!(stream.write_all(&[SOCKS5_VERSION, self.reply.as_u8(), 0x00]));
        try!(self.address.write_to(stream));

        Ok(())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.address.len() + 3
    }
}

#[inline]
fn parse_request_header<R: Read>(stream: &mut R) -> Result<(usize, Address), Error> {
    let atyp = match stream.read_u8() {
        Ok(atyp) => atyp,
        Err(_) => return Err(Error::new(Reply::GeneralFailure, "Error while reading address type"))
    };

    match atyp {
        SOCKS5_ADDR_TYPE_IPV4 => {
            let v4addr = Ipv4Addr::new(try!(stream.read_u8()),
                                       try!(stream.read_u8()),
                                       try!(stream.read_u8()),
                                       try!(stream.read_u8()));
            let port = try!(stream.read_u16::<BigEndian>());
            Ok((7usize, Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port)))))
        },
        SOCKS5_ADDR_TYPE_IPV6 => {
            let v6addr = Ipv6Addr::new(try!(stream.read_u16::<BigEndian>()),
                                       try!(stream.read_u16::<BigEndian>()),
                                       try!(stream.read_u16::<BigEndian>()),
                                       try!(stream.read_u16::<BigEndian>()),
                                       try!(stream.read_u16::<BigEndian>()),
                                       try!(stream.read_u16::<BigEndian>()),
                                       try!(stream.read_u16::<BigEndian>()),
                                       try!(stream.read_u16::<BigEndian>()));
            let port = try!(stream.read_u16::<BigEndian>());

            Ok((19usize, Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(v6addr, port, 0, 0)))))
        },
        SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            let addr_len = try!(stream.read_u8()) as usize;
            let mut raw_addr = Vec::with_capacity(addr_len);
            try!(stream.take(addr_len as u64).read_to_end(&mut raw_addr));
            let port = try!(stream.read_u16::<BigEndian>());

            let addr = match String::from_utf8(raw_addr) {
                Ok(addr) => addr,
                Err(..) => return Err(Error::new(Reply::GeneralFailure, "Invalid address encoding")),
            };

            Ok((4 + addr_len, Address::DomainNameAddress(addr, port)))
        },
        _ => {
            // Address type not supported
            Err(Error::new(Reply::AddressTypeNotSupported, "Not supported address type"))
        }
    }
}

#[inline]
fn write_addr<W: Write + Sized>(addr: &Address, buf: &mut W) -> io::Result<()> {
    match addr {
        &Address::SocketAddress(addr) => {
            match addr {
                SocketAddr::V4(addr) => {
                    try!(buf.write_all(&[SOCKS5_ADDR_TYPE_IPV4]));
                    try!(buf.write_all(&addr.ip().octets()));
                },
                SocketAddr::V6(addr) => {
                    try!(buf.write_u8(SOCKS5_ADDR_TYPE_IPV6));
                    for seg in addr.ip().segments().iter() {
                        try!(buf.write_u16::<BigEndian>(*seg));
                    }
                }
            }
            try!(buf.write_u16::<BigEndian>(addr.port()));
        },
        &Address::DomainNameAddress(ref dnaddr, port) => {
            try!(buf.write_u8(SOCKS5_ADDR_TYPE_DOMAIN_NAME));
            try!(buf.write_u8(dnaddr.len() as u8));
            try!(buf.write_all(dnaddr[..].as_bytes()));
            try!(buf.write_u16::<BigEndian>(port));
        }
    }

    Ok(())
}

#[inline]
fn get_addr_len(atyp: &Address) -> usize {
    match atyp {
        &Address::SocketAddress(addr) => {
            match addr {
                SocketAddr::V4(..) => 1 + 4 + 2,
                SocketAddr::V6(..) => 1 + 8 * 2 + 2
            }
        },
        &Address::DomainNameAddress(ref dmname, _) => {
            1 + 1 + dmname.len() + 2
        },
    }
}

// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 5  |    1     | 1 to 255 |
// +----+----------+----------|
#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}

impl HandshakeRequest {
    pub fn new(methods: Vec<u8>) -> HandshakeRequest {
        HandshakeRequest {
            methods: methods,
        }
    }

    pub fn read_from<R: Read>(stream: &mut R) -> io::Result<HandshakeRequest> {
        let ver = try!(stream.read_u8());
        if ver != SOCKS5_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid Socks5 version",
            ));
        }

        let nmet = try!(stream.read_u8());

        let mut methods = Vec::new();
        try!(stream.take(nmet as u64).read_to_end(&mut methods));

        Ok(HandshakeRequest {
            methods: methods,
        })
    }

    pub fn write_to(&self, stream: &mut Write) -> io::Result<()> {
        try!(stream.write_all(&[SOCKS5_VERSION, self.methods.len() as u8]));
        try!(stream.write_all(&self.methods[..]));

        Ok(())
    }
}

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
#[derive(Clone, Debug, Copy)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}

impl HandshakeResponse {
    pub fn new(cm: u8) -> HandshakeResponse {
        HandshakeResponse {
            chosen_method: cm,
        }
    }

    pub fn read_from<R: Read>(stream: &mut R) -> io::Result<HandshakeResponse> {
        let ver = try!(stream.read_u8());
        if ver != SOCKS5_VERSION {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid Socks5 version"));
        }

        let met = try!(stream.read_u8());

        Ok(HandshakeResponse {
            chosen_method: met,
        })
    }

    pub fn write_to(&self, stream: &mut Write) -> io::Result<()> {
        stream.write_all(&[SOCKS5_VERSION, self.chosen_method])
    }
}

#[derive(Clone, Debug)]
pub struct UdpAssociateHeader {
    pub frag: u8,
    pub address: Address,
}

impl UdpAssociateHeader {
    pub fn new(frag: u8, address: Address) -> UdpAssociateHeader {
        UdpAssociateHeader {
            frag: frag,
            address: address,
        }
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<UdpAssociateHeader, Error> {
        let _ = try!(reader.read_u8());
        let _ = try!(reader.read_u8());
        let frag = try!(reader.read_u8());

        Ok(UdpAssociateHeader::new(frag, try!(Address::read_from(reader))))
    }

    pub fn write_to<W: Write + Sized>(&self, writer: &mut W) -> io::Result<()> {
        try!(writer.write_all(&[0x00, 0x00, self.frag]));
        try!(self.address.write_to(writer));

        Ok(())
    }

    pub fn len(&self) -> usize {
        3 + self.address.len()
    }
}
