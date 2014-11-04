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

use std::fmt::{Show, Formatter, FormatError};
use std::io::net::ip::{SocketAddr, Port};
use std::io::net::ip::{Ipv4Addr, Ipv6Addr};
use std::io::{Reader, IoResult, IoError, OtherIoError};

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
#[deriving(Clone, Show, Copy)]
pub enum Command {
    TcpConnect,
    TcpBind,
    UdpAssociate,
}

impl Command {
    fn code(&self) -> u8 {
        match *self {
            TcpConnect => SOCKS5_CMD_TCP_CONNECT,
            TcpBind => SOCKS5_CMD_TCP_BIND,
            UdpAssociate => SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    fn from_code(code: u8) -> Option<Command> {
        match code {
            SOCKS5_CMD_TCP_CONNECT => Some(TcpConnect),
            SOCKS5_CMD_TCP_BIND => Some(TcpBind),
            SOCKS5_CMD_UDP_ASSOCIATE => Some(UdpAssociate),
            _ => None,
        }
    }
}

#[deriving(Clone, Show, Copy)]
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
    fn code(&self) -> u8 {
        match *self {
            Succeeded => SOCKS5_REPLY_SUCCEEDED,
            GeneralFailure => SOCKS5_REPLY_GENERAL_FAILURE,
            ConnectionNotAllowed => SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            NetworkUnreachable => SOCKS5_REPLY_NETWORK_UNREACHABLE,
            HostUnreachable => SOCKS5_REPLY_HOST_UNREACHABLE,
            ConnectionRefused => SOCKS5_REPLY_CONNECTION_REFUSED,
            TtlExpired => SOCKS5_REPLY_TTL_EXPIRED,
            CommandNotSupported => SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            AddressTypeNotSupported => SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
            OtherReply(c) => c,
        }
    }

    fn from_code(code: u8) -> Reply {
        match code {
            SOCKS5_REPLY_SUCCEEDED => Succeeded,
            SOCKS5_REPLY_GENERAL_FAILURE => GeneralFailure,
            SOCKS5_REPLY_CONNECTION_NOT_ALLOWED => ConnectionNotAllowed,
            SOCKS5_REPLY_NETWORK_UNREACHABLE => NetworkUnreachable,
            SOCKS5_REPLY_HOST_UNREACHABLE => HostUnreachable,
            SOCKS5_REPLY_CONNECTION_REFUSED => ConnectionRefused,
            SOCKS5_REPLY_TTL_EXPIRED => TtlExpired,
            SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => CommandNotSupported,
            SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => AddressTypeNotSupported,
            _ => OtherReply(code)
        }
    }
}

#[deriving(Clone)]
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

impl Show for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        write!(f, "{}", self.message)
    }
}

#[deriving(Clone, PartialEq, Eq, Hash)]
pub struct DomainNameAddr {
    pub domain_name: String,
    pub port: Port,
}

impl Show for DomainNameAddr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        write!(f, "{}:{}", self.domain_name, self.port)
    }
}

#[deriving(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainNameAddress(DomainNameAddr),
}

impl Address {
    pub fn read_from(reader: &mut Reader) -> Result<Address, Error> {
        match parse_request_header(reader) {
            Ok((_, addr)) => Ok(addr),
            Err(err) => Err(err),
        }
    }

    pub fn write_to(&self, writer: &mut Writer) -> IoResult<()> {
        write_addr(self, writer)
    }

    pub fn len(&self) -> uint {
        get_addr_len(self)
    }
}

impl Show for Address {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        match *self {
            SocketAddress(ref addr) => addr.fmt(f),
            DomainNameAddress(ref addr) => addr.fmt(f),
        }
    }
}

#[deriving(Clone, Show)]
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

    pub fn read_from(stream: &mut Reader) -> Result<TcpRequestHeader, Error> {
        let mut buf = [0u8, ..3];
        match stream.read(buf) {
            Ok(_) => (),
            Err(err) => return Err(Error::new(GeneralFailure, err.to_string().as_slice()))
        }
        let [ver, cmd, _] = buf;

        if ver != SOCKS5_VERSION {
            return Err(Error::new(ConnectionRefused, "Unsupported Socks version"));
        }

        Ok(TcpRequestHeader {
            command: match Command::from_code(cmd) {
                Some(c) => c,
                None => return Err(Error::new(CommandNotSupported, "Unsupported command")),
            },
            address: try!(Address::read_from(stream)),
        })
    }

    pub fn write_to(&self, stream: &mut Writer) -> IoResult<()> {
        try!(stream.write([SOCKS5_VERSION, self.command.code(), 0x00]));
        try!(self.address.write_to(stream));

        Ok(())
    }

    pub fn len(&self) -> uint {
        self.address.len() + 3
    }
}

#[deriving(Clone, Show)]
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

    pub fn read_from(stream: &mut Reader) -> Result<TcpResponseHeader, Error> {
        let mut buf = [0u8, ..3];
        match stream.read(buf) {
            Ok(_) => (),
            Err(err) => return Err(Error::new(GeneralFailure, err.to_string().as_slice()))
        }
        let [ver, reply_code, _] = buf;

        if ver != SOCKS5_VERSION {
            return Err(Error::new(ConnectionRefused, "Unsupported Socks version"));
        }

        Ok(TcpResponseHeader {
            reply: Reply::from_code(reply_code),
            address: try!(Address::read_from(stream)),
        })
    }

    pub fn write_to(&self, stream: &mut Writer) -> IoResult<()> {
        try!(stream.write([SOCKS5_VERSION, self.reply.code(), 0x00]));
        try!(self.address.write_to(stream));

        Ok(())
    }

    pub fn len(&self) -> uint {
        self.address.len() + 3
    }
}

fn parse_request_header(stream: &mut Reader) -> Result<(uint, Address), Error> {
    let atyp = match stream.read_byte() {
        Ok(atyp) => atyp,
        Err(_) => return Err(Error::new(GeneralFailure, "Error while reading address type"))
    };

    match atyp {
        SOCKS5_ADDR_TYPE_IPV4 => {
            let wrapper = || {
                let v4addr = Ipv4Addr(try!(stream.read_byte()),
                                      try!(stream.read_byte()),
                                      try!(stream.read_byte()),
                                      try!(stream.read_byte()));
                let port = try!(stream.read_be_u16());
                Ok((v4addr, port))
            };
            match wrapper() {
                Ok((v4addr, port)) => Ok((7u, SocketAddress(SocketAddr{ip: v4addr, port: port}))),
                Err(_) =>
                    Err(Error::new(GeneralFailure, "Error while parsing IPv4 address"))
            }
        },
        SOCKS5_ADDR_TYPE_IPV6 => {
            let wrapper = || {
                let v6addr = Ipv6Addr(try!(stream.read_be_u16()),
                                      try!(stream.read_be_u16()),
                                      try!(stream.read_be_u16()),
                                      try!(stream.read_be_u16()),
                                      try!(stream.read_be_u16()),
                                      try!(stream.read_be_u16()),
                                      try!(stream.read_be_u16()),
                                      try!(stream.read_be_u16()));
                let port = try!(stream.read_be_u16());
                Ok((v6addr, port))
            };

            match wrapper() {
                Ok((v6addr, port)) =>
                    Ok((19u, SocketAddress(SocketAddr{ip: v6addr, port: port}))),
                Err(_) =>
                    Err(Error::new(GeneralFailure, "Error while parsing IPv6 address"))
            }
        },
        SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            let wrapper = || {
                let addr_len = try!(stream.read_byte()) as uint;
                let raw_addr = try!(stream.read_exact(addr_len));
                let port = try!(stream.read_be_u16());

                Ok((addr_len, raw_addr, port))
            };

            match wrapper() {
                Ok((addr_len, raw_addr, port)) =>
                    Ok((4 + addr_len, DomainNameAddress(DomainNameAddr{
                                                            domain_name: String::from_utf8(raw_addr).unwrap(),
                                                            port: port,
                                                        }))),
                Err(_) => {
                    Err(Error::new(GeneralFailure, "Error while parsing domain name"))
                }
            }
        },
        _ => {
            // Address type not supported
            Err(Error::new(AddressTypeNotSupported, "Not supported address type"))
        }
    }
}

fn write_addr(addr: &Address, buf: &mut Writer) -> IoResult<()> {
    match addr {
        &SocketAddress(ref sockaddr) => {
            match sockaddr.ip {
                Ipv4Addr(v1, v2, v3, v4) => {
                    try!(buf.write([SOCKS5_ADDR_TYPE_IPV4,
                                        v1, v2, v3, v4]));
                },
                Ipv6Addr(v1, v2, v3, v4, v5, v6, v7, v8) => {
                    try!(buf.write_u8(SOCKS5_ADDR_TYPE_IPV6));
                    try!(buf.write_be_u16(v1));
                    try!(buf.write_be_u16(v2));
                    try!(buf.write_be_u16(v3));
                    try!(buf.write_be_u16(v4));
                    try!(buf.write_be_u16(v5));
                    try!(buf.write_be_u16(v6));
                    try!(buf.write_be_u16(v7));
                    try!(buf.write_be_u16(v8));
                }
            }
            try!(buf.write_be_u16(sockaddr.port));
        },
        &DomainNameAddress(ref dnaddr) => {
            try!(buf.write_u8(SOCKS5_ADDR_TYPE_DOMAIN_NAME));
            try!(buf.write_u8(dnaddr.domain_name.len() as u8));
            try!(buf.write_str(dnaddr.domain_name.as_slice()));
            try!(buf.write_be_u16(dnaddr.port));
        }
    }

    Ok(())
}

fn get_addr_len(atyp: &Address) -> uint {
    match atyp {
        &SocketAddress(ref sockaddr) => {
            match sockaddr.ip {
                Ipv4Addr(_, _, _, _) => 1 + 4 + 2,
                Ipv6Addr(_, _, _, _, _, _, _, _) => 1 + 8 * 2 + 2
            }
        },
        &DomainNameAddress(ref dmname) => {
            1 + 1 + dmname.domain_name.len() + 2
        },
    }
}

// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 5  |    1     | 1 to 255 |
// +----+----------+----------|
#[deriving(Clone, Show)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}

impl HandshakeRequest {
    pub fn new(methods: Vec<u8>) -> HandshakeRequest {
        HandshakeRequest {
            methods: methods,
        }
    }

    pub fn read_from(stream: &mut Reader) -> IoResult<HandshakeRequest> {
        let mut buf = [0, ..2];
        try!(stream.read(buf));
        let [ver, nmet] = buf;

        if ver != SOCKS5_VERSION {
            return Err(IoError {
                kind: OtherIoError,
                desc: "Invalid Socks5 version",
                detail: None,
            });
        }

        Ok(HandshakeRequest {
            methods: try!(stream.read_exact(nmet as uint)),
        })
    }

    pub fn write_to(&self, stream: &mut Writer) -> IoResult<()> {
        try!(stream.write([SOCKS5_VERSION, self.methods.len() as u8]));
        try!(stream.write(self.methods.as_slice()));

        Ok(())
    }
}

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
#[deriving(Clone, Show)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}

impl HandshakeResponse {
    pub fn new(cm: u8) -> HandshakeResponse {
        HandshakeResponse {
            chosen_method: cm,
        }
    }

    pub fn read_from(stream: &mut Reader) -> IoResult<HandshakeResponse> {
        let mut buf = [0, ..2];
        try!(stream.read(buf));
        let [ver, met] = buf;

        Ok(HandshakeResponse {
            chosen_method: met,
        })
    }

    pub fn write_to(&self, stream: &mut Writer) -> IoResult<()> {
        try!(stream.write([SOCKS5_VERSION, self.chosen_method]));

        Ok(())
    }
}

#[deriving(Clone, Show)]
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

    pub fn read_from(reader: &mut Reader) -> Result<UdpAssociateHeader, Error> {
        let mut buf = [0u8, ..3];
        match reader.read(buf) {
            Ok(_) => (),
            Err(err) => {
                return Err(Error::new(GeneralFailure, err.to_string().as_slice()));
            }
        }

        let [_, _, frag] = buf;

        Ok(UdpAssociateHeader::new(frag, try!(Address::read_from(reader))))
    }

    pub fn write_to(&self, writer: &mut Writer) -> IoResult<()> {
        try!(writer.write([0x00, 0x00, self.frag]));
        try!(self.address.write_to(writer));

        Ok(())
    }

    pub fn len(&self) -> uint {
        3 + self.address.len()
    }
}
