#![feature(phase)]

extern crate getopts;
#[phase(plugin, link)]
extern crate log;

use getopts::{optopt, optflag, getopts, usage, Matches};

use std::os;

use std::io::net::udp::UdpSocket;
use std::io::net::tcp::TcpStream;
use std::io::net::ip::SocketAddr;
use std::io::net::ip::{IpAddr, Ipv4Addr, Ipv6Addr, Port};
use std::io::net::addrinfo::get_host_addresses;
use std::io::{MemWriter, BufferedStream};
use std::io::stdio::{stdin, stdout};
use std::io::{IoResult, Reader, Writer};

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

#[deriving(Clone, PartialEq, Eq, Hash)]
pub enum AddressType {
    SocketAddress(SocketAddr),
    DomainNameAddress(DomainNameAddr),
}

fn write_addr(addr: &AddressType, writer: &mut Writer) -> IoResult<()> {
    match addr {
        &SocketAddress(ref ip) => {
            match ip.ip {
                Ipv4Addr(v1, v2, v3, v4) => {
                    try!(writer.write([SOCKS5_ADDR_TYPE_IPV4, v1, v2, v3, v4]));
                },
                Ipv6Addr(v1, v2, v3, v4, v5, v6, v7, v8) => {
                    try!(writer.write_u8(SOCKS5_ADDR_TYPE_IPV6));
                    try!(writer.write_be_u16(v1));
                    try!(writer.write_be_u16(v2));
                    try!(writer.write_be_u16(v3));
                    try!(writer.write_be_u16(v4));
                    try!(writer.write_be_u16(v5));
                    try!(writer.write_be_u16(v6));
                    try!(writer.write_be_u16(v7));
                    try!(writer.write_be_u16(v8));
                }
            }
            try!(writer.write_be_u16(ip.port));
        },
        &DomainNameAddress(ref domain_name) => {
            try!(writer.write_u8(SOCKS5_ADDR_TYPE_DOMAIN_NAME));
            try!(writer.write_u8(domain_name.domain_name.len() as u8));
            try!(writer.write(domain_name.domain_name.as_slice().as_bytes()));
            try!(writer.write_be_u16(domain_name.port));
        }
    }

    Ok(())
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

fn get_addr_len(response: &[u8]) -> uint {
    match response[0] {
        SOCKS5_ADDR_TYPE_IPV4 => {
            1 + 6
        },
        SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
            1 + response[1] as uint + 2
        },
        SOCKS5_ADDR_TYPE_IPV6 => {
            1 + 16 + 2
        }
        _ => {
            panic!("Invalid addr type {}", response[0]);
        }
    }
}

fn do_udp(matches: &Matches, svr_addr: &AddressType, proxy_addr: &SocketAddr) {
    let udp_proxy_addr = {
        let mut stream = BufferedStream::new(
                            TcpStream::connect(proxy_addr.ip.to_string().as_slice(), proxy_addr.port).unwrap());
        let mut buf = [0u8, ..0xffff];

        stream.write([SOCKS5_VERSION, 0x01, 0x00]).unwrap();
        stream.flush().unwrap();
        stream.read(buf).unwrap();
        if buf[1] != SOCKS5_AUTH_METHOD_NONE {
            panic!("Proxy server needs authentication");
        }

        stream.write([SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00]).unwrap();
        write_addr(svr_addr, &mut stream).unwrap();
        stream.flush().unwrap();

        let three_flag = stream.read_exact(3).unwrap();
        if three_flag[1] != SOCKS5_REPLY_SUCCEEDED {
            panic!("Failed with error code: {}", three_flag[1]);
        }

        let (_, paddr) = parse_request_header(&mut stream).unwrap();

        match paddr {
            SocketAddress(addr) => addr,
            DomainNameAddress(dmname) => {
                let addrs = get_host_addresses(dmname.domain_name.as_slice()).unwrap();
                SocketAddr {
                    ip: addrs.head().unwrap().clone(),
                    port: dmname.port,
                }
            }
        }
    };

    let local_addr = SocketAddr {
        ip: from_str(matches.opt_str("b").expect("Require local address").as_slice()).unwrap(),
        port: from_str(matches.opt_str("l").expect("Require local port").as_slice()).unwrap(),
    };

    let mut socket = UdpSocket::bind(local_addr).unwrap();

    let mut writer = MemWriter::new();
    writer.write([0x00u8, 0x00u8, 0x00u8]).unwrap();
    write_addr(svr_addr, &mut writer).unwrap();

    let inputs = stdin().read_to_end().unwrap();
    writer.write(inputs.as_slice()).unwrap();

    socket.send_to(writer.unwrap().as_slice(), udp_proxy_addr.clone()).unwrap();

    let mut buf = [0u8, ..0xffff];
    let (len, _) = socket.recv_from(buf).unwrap();

    let response = buf.slice_to(len).slice_from(3);

    let addr_len = get_addr_len(response);

    stdout().write(response.slice_from(addr_len)).unwrap();
}

fn do_tcp(_: &Matches, svr_addr: &AddressType, proxy_addr: &SocketAddr) {
    let mut stream = TcpStream::connect(proxy_addr.ip.to_string().as_slice(), proxy_addr.port).unwrap();
    let mut buf = [0u8, ..0xffff];

    stream.write([SOCKS5_VERSION, 0x01, 0x00]).unwrap();
    stream.read(buf).unwrap();
    if buf[1] != SOCKS5_AUTH_METHOD_NONE {
        panic!("Proxy server needs authentication");
    }

    stream.write([SOCKS5_VERSION, SOCKS5_CMD_TCP_CONNECT, 0x00]).unwrap();
    write_addr(svr_addr, &mut stream).unwrap();

    let inputs = stdin().read_to_end().unwrap();
    stream.write(inputs.as_slice()).unwrap();

    let mut output = stdout();

    {
        let buf_len = stream.read_at_least(1, buf).unwrap();
        let header = buf.slice_to(buf_len);

        if header[1] != SOCKS5_REPLY_SUCCEEDED {
            panic!("Failed with error: {}", header[1]);
        }

        let addr_len = get_addr_len(header.slice_from(3));
        output.write(header.slice_from(3 + addr_len)).unwrap();
    }

    loop {
        match stream.read(buf) {
            Ok(len) => {
                output.write(buf.slice_to(len)).unwrap();
            },
            Err(..) => {
                break;
            }
        }
    }
    println!("");
}

fn main() {

    let opts = [
        optflag("h", "help", "Print help message"),
        optopt("s", "server-addr", "Server address", ""),
        optopt("p", "server-port", "Server port", ""),
        optopt("b", "local-addr", "Local address for binding", ""),
        optopt("l", "local-port", "Local port for binding", ""),
        optopt("x", "proxy-addr", "Proxy address", ""),
        optopt("o", "proxy-port", "Proxy port", ""),
        optopt("t", "protocol", "Protocol to use", "tcp"),
    ];

    let matches = getopts(os::args().tail(), opts).unwrap();

    if matches.opt_present("h") {
        println!("{}", usage(format!("Usage: {} [Options]", os::args()[0]).as_slice(),
                            opts));
        return;
    }

    let is_tcp = match matches.opt_str("t").expect("Required to specify protocol").as_slice() {
        "tcp" => true,
        "udp" => false,
        _ => panic!("Unsupported protocol")
    };

    let proxy_addr = SocketAddr {
        ip: from_str(matches.opt_str("x").expect("Require proxy address").as_slice()).unwrap(),
        port: from_str(matches.opt_str("o").expect("Require proxy port").as_slice()).unwrap(),
    };

    let svr_port: Port = from_str(matches.opt_str("p").expect("Require server port").as_slice()).unwrap();
    let svr_addr = match from_str::<IpAddr>(matches.opt_str("s").expect("Require server address").as_slice()) {
        Some(ip) => SocketAddress(SocketAddr {ip: ip, port: svr_port}),
        None => DomainNameAddress(DomainNameAddr { domain_name: matches.opt_str("s").unwrap(), port: svr_port}),
    };

    if is_tcp {
        do_tcp(&matches, &svr_addr, &proxy_addr);
    } else {
        do_udp(&matches, &svr_addr, &proxy_addr);
    }
}
