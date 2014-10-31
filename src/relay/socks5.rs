// The MIT License (MIT)

// Copyright (c) 2014 Y. T. CHUNG

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

pub struct DomainNameAddr {
    pub domain_name: String,
    pub port: Port,
}

impl Show for DomainNameAddr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        f.write(format!("{}:{}", self.domain_name, self.port).as_slice().as_bytes())
    }
}

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

pub fn parse_request_header(buf: &[u8]) -> Result<(uint, AddressType), u8> {
    let atyp = buf[0];
    match atyp {
        SOCKS5_ADDR_TYPE_IPV4 => {
            if buf.len() < 7 {
                error!("Invalid IPv4 header");
                return Err(SOCKS5_REPLY_GENERAL_FAILURE);
            }

            let raw_addr = buf.slice(1, 5);
            let v4addr = Ipv4Addr(raw_addr[0], raw_addr[1], raw_addr[2], raw_addr[3]);

            let raw_port = buf.slice(5, 7);
            let port = (raw_port[0] as u16 << 8) | raw_port[1] as u16;

            Ok((7u, SocketAddress(SocketAddr{ip: v4addr, port: port})))
        },
        SOCKS5_ADDR_TYPE_IPV6 => {
            if buf.len() < 19 {
                error!("Invalid IPv6 header");
                return Err(SOCKS5_REPLY_GENERAL_FAILURE);
            }

            let raw_addr = buf.slice(1, 17);
            let v6addr = Ipv6Addr((raw_addr[0] as u16 << 8) | raw_addr[1] as u16,
                                  (raw_addr[2] as u16 << 8) | raw_addr[3] as u16,
                                  (raw_addr[4] as u16 << 8) | raw_addr[5] as u16,
                                  (raw_addr[6] as u16 << 8) | raw_addr[7] as u16,
                                  (raw_addr[8] as u16 << 8) | raw_addr[9] as u16,
                                  (raw_addr[10] as u16 << 8) | raw_addr[11] as u16,
                                  (raw_addr[12] as u16 << 8) | raw_addr[13] as u16,
                                  (raw_addr[14] as u16 << 8) | raw_addr[15] as u16);

            let raw_port = buf.slice(17, 19);
            // Big Endian
            let port = (raw_port[0] as u16 << 8) | raw_port[1] as u16;

            Ok((19u, SocketAddress(SocketAddr{ip: v6addr, port: port})))
        },
        SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            let addr_len = buf[1] as uint;
            if buf.len() < 4 + addr_len {
                error!("Invalid domain name header");
                return Err(SOCKS5_REPLY_GENERAL_FAILURE);
            }
            let raw_addr = buf.slice(2, 2 + addr_len);
            let raw_port = buf.slice(2 + addr_len, 4 + addr_len);
            let port = (raw_port[0] as u16 << 8) | raw_port[1] as u16;

            Ok((4 + addr_len, DomainNameAddress(DomainNameAddr{
                                                domain_name: String::from_utf8(raw_addr.to_vec()).unwrap(),
                                                port: port,
                                            })))
        },
        _ => {
            // Address type not supported
            Err(SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
        }
    }
}
