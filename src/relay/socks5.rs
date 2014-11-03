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
use std::io::{Reader, IoResult};

pub const SOCKS5_VERSION : u8 = 0x05;

pub const SOCKS5_AUTH_METHOD_NONE            : u8 = 0x00;
pub const SOCKS5_AUTH_METHOD_GSSAPI          : u8 = 0x01;
pub const SOCKS5_AUTH_METHOD_PASSWORD        : u8 = 0x02;
pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE  : u8 = 0xff;

pub const SOCKS5_CMD_TCP_CONNECT   : u8 = 0x01;
pub const SOCKS5_CMD_TCP_BIND      : u8 = 0x02;
pub const SOCKS5_CMD_UDP_ASSOCIATE : u8 = 0x03;

pub const SOCKS5_ADDR_TYPE_IPV4        : u8 = 0x01;
pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME : u8 = 0x03;
pub const SOCKS5_ADDR_TYPE_IPV6        : u8 = 0x04;

pub const SOCKS5_REPLY_SUCCEEDED                     : u8 = 0x00;
pub const SOCKS5_REPLY_GENERAL_FAILURE               : u8 = 0x01;
pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED        : u8 = 0x02;
pub const SOCKS5_REPLY_NETWORK_UNREACHABLE           : u8 = 0x03;
pub const SOCKS5_REPLY_HOST_UNREACHABLE              : u8 = 0x04;
pub const SOCKS5_REPLY_CONNECTION_REFUSED            : u8 = 0x05;
pub const SOCKS5_REPLY_TTL_EXPIRED                   : u8 = 0x06;
pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED         : u8 = 0x07;
pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED    : u8 = 0x08;

#[allow(dead_code)]
#[deriving(Show)]
pub enum CommandType {
    TcpConnect,
    TcpBind,
    UdpAssociate,
}

#[deriving(Show, Clone)]
pub struct Error {
    pub code: u8,
    pub message: String,
}

impl Error {
    pub fn new(code: u8, message: &str) -> Error {
        Error {
            code: code,
            message: message.to_string(),
        }
    }
}

#[deriving(Clone, PartialEq, Eq, Hash)]
pub struct DomainNameAddr {
    pub domain_name: String,
    pub port: Port,
}

impl Show for DomainNameAddr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        f.write(format!("{}:{}", self.domain_name, self.port).as_slice().as_bytes())
    }
}

#[deriving(Clone, PartialEq, Eq, Hash)]
pub enum AddressType {
    SocketAddress(SocketAddr),
    DomainNameAddress(DomainNameAddr),
}

impl Show for AddressType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        match *self {
            SocketAddress(ref addr) => addr.fmt(f),
            DomainNameAddress(ref addr) => addr.fmt(f),
        }
    }
}

pub fn parse_request_header(stream: &mut Reader) -> Result<(uint, AddressType), Error> {
    let atyp = match stream.read_byte() {
        Ok(atyp) => atyp,
        Err(_) => return Err(Error::new(SOCKS5_REPLY_GENERAL_FAILURE, "Error while reading address type"))
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
                    Err(Error::new(SOCKS5_REPLY_GENERAL_FAILURE, "Error while parsing IPv4 address"))
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
                    Err(Error::new(SOCKS5_REPLY_GENERAL_FAILURE, "Error while parsing IPv6 address"))
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
                    Err(Error::new(SOCKS5_REPLY_GENERAL_FAILURE, "Error while parsing domain name"))
                }
            }
        },
        _ => {
            // Address type not supported
            Err(Error::new(SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED, "Not supported address type"))
        }
    }
}

pub fn write_addr(addr: &AddressType, buf: &mut Writer) -> IoResult<()> {
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
