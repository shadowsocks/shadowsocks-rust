pub use self::local::RelayLocal;
pub use self::server::RelayServer;

use std::fmt::{Show, Formatter, FormatError};
use std::io::net::ip::{SocketAddr, Port};
use std::io::TcpStream;
use std::io::net::ip::{Ipv4Addr, Ipv6Addr};

pub mod tcprelay;
pub mod udprelay;
pub mod local;
pub mod server;

pub trait Relay {
    fn run(&self);
}

pub const SOCK5_VERSION : u8 = 0x05;

pub const SOCK5_AUTH_METHOD_NONE            : u8 = 0x00;
pub const SOCK5_AUTH_METHOD_GSSAPI          : u8 = 0x01;
pub const SOCK5_AUTH_METHOD_PASSWORD        : u8 = 0x02;
pub const SOCK5_AUTH_METHOD_NOT_ACCEPTABLE  : u8 = 0xff;

pub const SOCK5_CMD_TCP_CONNECT   : u8 = 0x01;
pub const SOCK5_CMD_TCP_BIND      : u8 = 0x02;
pub const SOCK5_CMD_UDP_ASSOCIATE : u8 = 0x03;

pub const SOCK5_ADDR_TYPE_IPV4        : u8 = 0x01;
pub const SOCK5_ADDR_TYPE_DOMAIN_NAME : u8 = 0x03;
pub const SOCK5_ADDR_TYPE_IPV6        : u8 = 0x04;

pub const SOCK5_REPLY_SUCCEEDED                     : u8 = 0x00;
pub const SOCK5_REPLY_GENERAL_FAILURE               : u8 = 0x01;
pub const SOCK5_REPLY_CONNECTION_NOT_ALLOWED        : u8 = 0x02;
pub const SOCK5_REPLY_NETWORK_UNREACHABLE           : u8 = 0x03;
pub const SOCK5_REPLY_HOST_UNREACHABLE              : u8 = 0x04;
pub const SOCK5_REPLY_CONNECTION_REFUSED            : u8 = 0x05;
pub const SOCK5_REPLY_TTL_EXPIRED                   : u8 = 0x06;
pub const SOCK5_REPLY_COMMAND_NOT_SUPPORTED         : u8 = 0x07;
pub const SOCK5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED    : u8 = 0x08;

#[deriving(Show)]
pub enum Sock5CmdType {
    Sock5CmdTcpConnect,
    Sock5CmdTcpBind,
    Sock5CmdUdpAssociate,
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

#[deriving(Show)]
pub enum Sock5AddrType {
    Sock5SocketAddr(SocketAddr),
    Sock5DomainNameAddr(DomainNameAddr),
}

pub fn parse_request_header(buf: &[u8]) -> Result<(uint, Sock5AddrType), u8> {
    let atyp = buf[0];
    match atyp {
        SOCK5_ADDR_TYPE_IPV4 => {
            if buf.len() < 7 {
                fail!("Invalid header");
            }

            let raw_addr = buf.slice(1, 5);
            let v4addr = Ipv4Addr(raw_addr[0], raw_addr[1], raw_addr[2], raw_addr[3]);

            let raw_port = buf.slice(5, 7);
            let port = (raw_port[0] as u16 << 8) | raw_port[1] as u16;

            Ok((7u, Sock5SocketAddr(SocketAddr{ip: v4addr, port: port})))
        },
        SOCK5_ADDR_TYPE_IPV6 => {
            if buf.len() < 19 {
                fail!("Invalid header");
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

            Ok((19u, Sock5SocketAddr(SocketAddr{ip: v6addr, port: port})))
        },
        SOCK5_ADDR_TYPE_DOMAIN_NAME => {
            let addr_len = buf[1] as uint;
            if buf.len() < 4 + addr_len {
                fail!("Invalid header");
            }
            let raw_addr = buf.slice(2, 2 + addr_len);
            let raw_port = buf.slice(2 + addr_len, 4 + addr_len);
            let port = (raw_port[0] as u16 << 8) | raw_port[1] as u16;

            Ok((4 + addr_len, Sock5DomainNameAddr(DomainNameAddr{
                                                domain_name: String::from_utf8(raw_addr.to_vec()).unwrap(),
                                                port: port,
                                            })))
        },
        _ => {
            // Address type not supported
            Err(SOCK5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED)
        }
    }
}

pub fn send_error_reply(stream: &mut TcpStream, err_code: u8) {
    let reply = [SOCK5_VERSION, err_code, 0x00];
    stream.write(reply).ok().expect("Error occurs while sending errors");
}
