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
use std::io::MemWriter;
use std::io::stdio::{stdin, stdout};
use std::io::{IoResult, Reader, Writer};

enum AddrType {
    DomainName(String),
    Ip(IpAddr),
}

fn write_addr(addr: &AddrType, port: Port, writer: &mut Writer) -> IoResult<()> {
    match addr {
        &Ip(ref ip) => {
            match ip {
                &Ipv4Addr(v1, v2, v3, v4) => {
                    try!(writer.write([0x01u8, v1, v2, v3, v4]));
                },
                &Ipv6Addr(v1, v2, v3, v4, v5, v6, v7, v8) => {
                    try!(writer.write_u8(0x04u8));
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
        },
        &DomainName(ref domain_name) => {
            try!(writer.write_u8(0x03u8));
            try!(writer.write_u8(domain_name.len() as u8));
            try!(writer.write(domain_name.as_slice().as_bytes()));
        }
    }
    try!(writer.write_be_u16(port));

    Ok(())
}

fn get_addr_len(response: &[u8]) -> uint {
    match response[0] {
        0x01u8 => {
            1 + 6
        },
        0x03u8 => {
            1 + response[1] as uint + 2
        },
        0x04u8 => {
            1 + 16 + 2
        }
        _ => {
            panic!("Invalid addr type {}", response[0]);
        }
    }
}

fn do_udp(matches: &Matches, svr_addr: &AddrType, svr_port: Port, proxy_addr: &SocketAddr) {
    let local_addr = SocketAddr {
        ip: from_str(matches.opt_str("b").unwrap().as_slice()).unwrap(),
        port: from_str(matches.opt_str("l").unwrap().as_slice()).unwrap(),
    };

    let mut socket = UdpSocket::bind(local_addr).unwrap();

    let mut writer = MemWriter::new();
    writer.write([0x00u8, 0x00u8, 0x00u8]).unwrap();
    write_addr(svr_addr, svr_port, &mut writer).unwrap();

    let inputs = stdin().read_to_end().unwrap();
    writer.write(inputs.as_slice()).unwrap();

    socket.send_to(writer.unwrap().as_slice(), proxy_addr.clone()).unwrap();

    let mut buf = [0u8, ..0xffff];
    let (len, _) = socket.recv_from(buf).unwrap();

    let response = buf.slice_to(len).slice_from(3);

    let addr_len = get_addr_len(response);

    stdout().write(response.slice_from(addr_len)).unwrap();
}

fn do_tcp(_: &Matches, svr_addr: &AddrType, svr_port: Port, proxy_addr: &SocketAddr) {
    let mut stream = TcpStream::connect(proxy_addr.ip.to_string().as_slice(), proxy_addr.port).unwrap();
    let mut buf = [0u8, ..0xffff];

    stream.write([0x05, 0x01, 0x00]).unwrap();
    stream.read(buf).unwrap();
    if buf[1] != 0x00u8 {
        panic!("Proxy server needs authentication");
    }

    stream.write([0x05, 0x01, 0x00]).unwrap();
    write_addr(svr_addr, svr_port, &mut stream).unwrap();

    let inputs = stdin().read_to_end().unwrap();
    stream.write(inputs.as_slice()).unwrap();

    let mut output = stdout();

    {
        let buf_len = stream.read_at_least(1, buf).unwrap();
        let header = buf.slice_to(buf_len);

        if header[1] != 0x00u8 {
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

    let is_tcp = match matches.opt_str("t").unwrap().as_slice() {
        "tcp" => true,
        "udp" => false,
        _ => panic!("Unsupported protocol")
    };

    let proxy_addr = SocketAddr {
        ip: from_str(matches.opt_str("x").unwrap().as_slice()).unwrap(),
        port: from_str(matches.opt_str("o").unwrap().as_slice()).unwrap(),
    };

    let svr_port: Port = from_str(matches.opt_str("p").unwrap().as_slice()).unwrap();
    let svr_addr = match from_str::<IpAddr>(matches.opt_str("s").unwrap().as_slice()) {
        Some(ip) => Ip(ip),
        None => DomainName(matches.opt_str("s").unwrap()),
    };

    if is_tcp {
        do_tcp(&matches, &svr_addr, svr_port, &proxy_addr);
    } else {
        do_udp(&matches, &svr_addr, svr_port, &proxy_addr);
    }
}
