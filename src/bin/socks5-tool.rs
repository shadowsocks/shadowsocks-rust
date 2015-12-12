#![feature(lookup_host, ip_addr)]

extern crate clap;
#[macro_use]
extern crate log;

extern crate shadowsocks;

use clap::{App, Arg};

use std::net::UdpSocket;
use std::net::TcpStream;
use std::net::{IpAddr, SocketAddr};
use std::net::lookup_host;
use std::io::Cursor;
use std::io::stdout;
use std::io::{Write, self};

use shadowsocks::relay::socks5::*;

fn do_tcp(svr_addr: &Address, proxy_addr: &SocketAddr, msg: &str) {
    let mut proxy_stream = TcpStream::connect(proxy_addr).unwrap();

    let shake_req = HandshakeRequest::new(vec![0x00]);
    shake_req.write_to(&mut proxy_stream).unwrap();
    let shake_resp = HandshakeResponse::read_from(&mut proxy_stream).unwrap();

    if shake_resp.chosen_method != 0x00 {
        panic!("Proxy server needs authentication");
    }

    let req_header = TcpRequestHeader::new(Command::TcpConnect, svr_addr.clone());
    req_header.write_to(&mut proxy_stream).unwrap();
    proxy_stream.write(msg.as_bytes()).unwrap();

    let resp_header = TcpResponseHeader::read_from(&mut proxy_stream).unwrap();
    match resp_header.reply {
        Reply::Succeeded => {},
        _ => {
            panic!("Failed with error {:?}", resp_header.reply);
        }
    }

    io::copy(&mut proxy_stream, &mut stdout()).unwrap();
}

fn do_udp(svr_addr: &Address, proxy_addr: &SocketAddr, local_addr: &SocketAddr, msg: &str) {
    let udp_proxy_addr = {
        let mut proxy_stream = TcpStream::connect(proxy_addr).unwrap();

        let shake_req = HandshakeRequest::new(vec![0x00]);
        shake_req.write_to(&mut proxy_stream).unwrap();
        let shake_resp = HandshakeResponse::read_from(&mut proxy_stream).unwrap();

        if shake_resp.chosen_method != 0x00 {
            panic!("Proxy server needs authentication");
        }

        let req_header = TcpRequestHeader::new(Command::UdpAssociate, svr_addr.clone());
        req_header.write_to(&mut proxy_stream).unwrap();

        let resp_header = TcpResponseHeader::read_from(&mut proxy_stream).unwrap();
        match resp_header.reply {
            Reply::Succeeded => {},
            _ => {
                panic!("Failed with error {:?}", resp_header.reply);
            }
        }

        resp_header.address
    };

    let udp_socket = UdpSocket::bind(local_addr).unwrap();

    let proxy_real_addr = match udp_proxy_addr {
        Address::SocketAddress(sock) => sock,
        Address::DomainNameAddress(dm, port) => {
            let host = match lookup_host(&dm) {
                Ok(mut hosts) => {
                    match hosts.next() {
                        Some(h) => h.unwrap(),
                        None => panic!("No hosts could be found by {:?}", dm),
                    }
                },
                Err(err) => panic!("LookupHost: {:?}", err),
            };

            SocketAddr::new(host.ip(), port)
        }
    };

    let mut bufw = Vec::new();
    let udp_header = UdpAssociateHeader::new(0, svr_addr.clone());
    udp_header.write_to(&mut bufw).unwrap();
    bufw.write(msg.as_bytes()).unwrap();
    udp_socket.send_to(&bufw, proxy_real_addr).unwrap();

    let mut buf = [0; 0xffff];
    let (len, _) = udp_socket.recv_from(&mut buf).unwrap();
    println!("Got buf: {:?}", &buf[..len]);

    let mut bufr = Cursor::new(&buf[..len]);
    let _ = UdpAssociateHeader::read_from(&mut bufr).unwrap();

    io::copy(&mut bufr, &mut stdout()).unwrap();
}

fn main() {

    let matches = App::new("socks5-tool")
                    .author("Y. T. Chung <zonyitoo@gmail.com>")
                    .about("Socks5 protocol test tool")
                    .arg(Arg::with_name("SERVER_ADDR").short("s").long("server-addr")
                            .takes_value(true)
                            .required(true)
                            .help("Server address"))
                    .arg(Arg::with_name("SERVER_PORT").short("p").long("server-port")
                            .takes_value(true)
                            .required(true)
                            .help("Server port"))
                    .arg(Arg::with_name("PROXY_ADDR").short("x").long("proxy-addr")
                            .takes_value(true)
                            .required(true)
                            .help("Proxy address"))
                    .arg(Arg::with_name("LOCAL_ADDR").short("b").long("local-addr")
                            .takes_value(true)
                            .required(false)
                            .help("Local address"))
                    .arg(Arg::with_name("PROTOCOL").short("t").long("protocol")
                            .takes_value(true)
                            .required(true)
                            .help("Protocol to use"))
                    .arg(Arg::with_name("MESSAGE").short("m").long("message")
                            .takes_value(true)
                            .required(true)
                            .help("Message to be sent"))
                    .get_matches();

    let is_tcp = match matches.value_of("PROTOCOL").unwrap() {
        "tcp" => true,
        "udp" => false,
        protocol => panic!("Unsupported protocol {:?}", protocol)
    };

    let proxy_addr: SocketAddr = matches.value_of("PROXY_ADDR").unwrap().parse().unwrap();

    let svr_port: u16 = matches.value_of("SERVER_PORT").unwrap().parse().unwrap();
    let svr_addr_str = matches.value_of("SERVER_ADDR").unwrap();
    let svr_addr = match svr_addr_str.parse::<IpAddr>() {
        Ok(ip) => Address::SocketAddress(SocketAddr::new(ip, svr_port)),
        Err(..) => Address::DomainNameAddress(svr_addr_str.to_owned(), svr_port),
    };

    let msg = matches.value_of("MESSAGE").unwrap();

    if is_tcp {
        do_tcp(&svr_addr, &proxy_addr, msg);
    } else {
        let local_addr: SocketAddr = matches.value_of("LOCAL_ADDR").unwrap().parse().unwrap();
        do_udp(&svr_addr, &proxy_addr, &local_addr, msg);
    }
}
