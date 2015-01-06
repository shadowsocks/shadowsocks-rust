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

use std::fmt::{self, Show, Formatter};
use std::io::net::ip::{IpAddr, Port};
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
#[derive(Clone, Show, Copy)]
pub enum Command {
    TcpConnect,
    TcpBind,
    UdpAssociate,
}

impl Command {
    fn code(&self) -> u8 {
        match *self {
            Command::TcpConnect => SOCKS5_CMD_TCP_CONNECT,
            Command::TcpBind => SOCKS5_CMD_TCP_BIND,
            Command::UdpAssociate => SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    fn from_code(code: u8) -> Option<Command> {
        match code {
            SOCKS5_CMD_TCP_CONNECT => Some(Command::TcpConnect),
            SOCKS5_CMD_TCP_BIND => Some(Command::TcpBind),
            SOCKS5_CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

#[derive(Clone, Show, Copy)]
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

    fn from_code(code: u8) -> Reply {
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

impl Show for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

macro_rules! try_io{
    ($do_io:expr, $errtype:expr, $message:expr) => ( {
        let io_result = $do_io;
        let errtype = $errtype;
        let message = $message;
        match io_result {
            Ok(ret) => { ret },
            Err(err) => {
                return Err(Error::new(errtype, message));
            }
        }
    });
    ($do_io:expr, $errtype:expr) => ( {
        let io_result = $do_io;
        let errtype = $errtype;
        match io_result {
            Ok(ret) => { ret },
            Err(err) => {
                return Err(Error::new(errtype, err.desc));
            }
        }
    });
    ($do_io:expr) => ( {
        let io_result = $do_io;
        match io_result {
            Ok(ret) => { ret },
            Err(err) => {
                return Err(Error::new(Reply::GeneralFailure, err.desc));
            }
        }
    });
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketAddress(IpAddr, Port),
    DomainNameAddress(String, Port),
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
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref ip, ref port) => write!(f, "{}:{}", ip, port),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

#[derive(Clone, Show)]
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
        let mut buf = [0u8; 3];
        match stream.read(&mut buf) {
            Ok(_) => (),
            Err(err) => return Err(Error::new(Reply::GeneralFailure, err.to_string().as_slice()))
        }
        let [ver, cmd, _] = buf;

        if ver != SOCKS5_VERSION {
            return Err(Error::new(Reply::ConnectionRefused, "Unsupported Socks version"));
        }

        Ok(TcpRequestHeader {
            command: match Command::from_code(cmd) {
                Some(c) => c,
                None => return Err(Error::new(Reply::CommandNotSupported, "Unsupported command")),
            },
            address: try!(Address::read_from(stream)),
        })
    }

    pub fn write_to(&self, stream: &mut Writer) -> IoResult<()> {
        try!(stream.write(&[SOCKS5_VERSION, self.command.code(), 0x00]));
        try!(self.address.write_to(stream));

        Ok(())
    }

    pub fn len(&self) -> uint {
        self.address.len() + 3
    }
}

#[derive(Clone, Show)]
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
        let mut buf = [0u8; 3];
        match stream.read(&mut buf) {
            Ok(_) => (),
            Err(err) => return Err(Error::new(Reply::GeneralFailure, err.to_string().as_slice()))
        }
        let [ver, reply_code, _] = buf;

        if ver != SOCKS5_VERSION {
            return Err(Error::new(Reply::ConnectionRefused, "Unsupported Socks version"));
        }

        Ok(TcpResponseHeader {
            reply: Reply::from_code(reply_code),
            address: try!(Address::read_from(stream)),
        })
    }

    pub fn write_to(&self, stream: &mut Writer) -> IoResult<()> {
        try!(stream.write(&[SOCKS5_VERSION, self.reply.code(), 0x00]));
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
        Err(_) => return Err(Error::new(Reply::GeneralFailure, "Error while reading address type"))
    };

    match atyp {
        SOCKS5_ADDR_TYPE_IPV4 => {
            let v4addr = Ipv4Addr(try_io!(stream.read_byte(), Reply::GeneralFailure),
                                  try_io!(stream.read_byte(), Reply::GeneralFailure),
                                  try_io!(stream.read_byte(), Reply::GeneralFailure),
                                  try_io!(stream.read_byte(), Reply::GeneralFailure));
            let port = try_io!(stream.read_be_u16(), Reply::GeneralFailure);
            Ok((7u, Address::SocketAddress(v4addr, port)))
        },
        SOCKS5_ADDR_TYPE_IPV6 => {
            let v6addr = Ipv6Addr(try_io!(stream.read_be_u16()),
                                  try_io!(stream.read_be_u16()),
                                  try_io!(stream.read_be_u16()),
                                  try_io!(stream.read_be_u16()),
                                  try_io!(stream.read_be_u16()),
                                  try_io!(stream.read_be_u16()),
                                  try_io!(stream.read_be_u16()),
                                  try_io!(stream.read_be_u16()));
            let port = try_io!(stream.read_be_u16());

            Ok((19u, Address::SocketAddress(v6addr, port)))
        },
        SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            let addr_len = try_io!(stream.read_byte()) as uint;
            let raw_addr = try_io!(stream.read_exact(addr_len));
            let port = try_io!(stream.read_be_u16());

            Ok((4 + addr_len, Address::DomainNameAddress(String::from_utf8(raw_addr).unwrap(),
                                                port,
                                                )))
        },
        _ => {
            // Address type not supported
            Err(Error::new(Reply::AddressTypeNotSupported, "Not supported address type"))
        }
    }
}

fn write_addr(addr: &Address, buf: &mut Writer) -> IoResult<()> {
    match addr {
        &Address::SocketAddress(ip, port) => {
            match ip {
                Ipv4Addr(v1, v2, v3, v4) => {
                    try!(buf.write(&[SOCKS5_ADDR_TYPE_IPV4,
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
            try!(buf.write_be_u16(port));
        },
        &Address::DomainNameAddress(ref dnaddr, port) => {
            try!(buf.write_u8(SOCKS5_ADDR_TYPE_DOMAIN_NAME));
            try!(buf.write_u8(dnaddr.len() as u8));
            try!(buf.write_str(dnaddr.as_slice()));
            try!(buf.write_be_u16(port));
        }
    }

    Ok(())
}

fn get_addr_len(atyp: &Address) -> uint {
    match atyp {
        &Address::SocketAddress(ip, _) => {
            match ip {
                Ipv4Addr(_, _, _, _) => 1 + 4 + 2,
                Ipv6Addr(_, _, _, _, _, _, _, _) => 1 + 8 * 2 + 2
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
#[derive(Clone, Show)]
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
        let mut buf = [0; 2];
        try!(stream.read(&mut buf));
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
        try!(stream.write(&[SOCKS5_VERSION, self.methods.len() as u8]));
        try!(stream.write(self.methods.as_slice()));

        Ok(())
    }
}

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
#[derive(Clone, Show, Copy)]
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
        let mut buf = [0; 2];
        try!(stream.read(&mut buf));
        let [ver, met] = buf;

        if ver != SOCKS5_VERSION {
            return Err(IoError {kind: OtherIoError, desc: "Invalid Socks5 version", detail: None});
        }

        Ok(HandshakeResponse {
            chosen_method: met,
        })
    }

    pub fn write_to(&self, stream: &mut Writer) -> IoResult<()> {
        try!(stream.write(&[SOCKS5_VERSION, self.chosen_method]));

        Ok(())
    }
}

#[derive(Clone, Show)]
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
        let mut buf = [0u8; 3];
        match reader.read(&mut buf) {
            Ok(_) => (),
            Err(err) => {
                return Err(Error::new(Reply::GeneralFailure, err.to_string().as_slice()));
            }
        }

        let [_, _, frag] = buf;

        Ok(UdpAssociateHeader::new(frag, try!(Address::read_from(reader))))
    }

    pub fn write_to(&self, writer: &mut Writer) -> IoResult<()> {
        try!(writer.write(&[0x00, 0x00, self.frag]));
        try!(self.address.write_to(writer));

        Ok(())
    }

    pub fn len(&self) -> uint {
        3 + self.address.len()
    }
}
