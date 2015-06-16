#![feature(lookup_host, ip_addr)]
extern crate getopts;
#[macro_use]
extern crate log;

extern crate shadowsocks;

use getopts::{Options, Matches};

use std::env;

use std::net::UdpSocket;
use std::net::TcpStream;
use std::net::{IpAddr, SocketAddr};
use std::net::lookup_host;
use std::io::Cursor;
use std::io::{stdin, stdout};
use std::io::{Read, Write, self};

use shadowsocks::relay::socks5::*;

fn do_tcp(_: &Matches, svr_addr: &Address, proxy_addr: &SocketAddr) {
    let mut proxy_stream = TcpStream::connect(proxy_addr).unwrap();

    let shake_req = HandshakeRequest::new(vec![0x00]);
    shake_req.write_to(&mut proxy_stream).unwrap();
    let shake_resp = HandshakeResponse::read_from(&mut proxy_stream).unwrap();

    if shake_resp.chosen_method != 0x00 {
        panic!("Proxy server needs authentication");
    }

    let mut data = Vec::new();
    stdin().read_to_end(&mut data).unwrap();

    let req_header = TcpRequestHeader::new(Command::TcpConnect, svr_addr.clone());
    req_header.write_to(&mut proxy_stream).unwrap();
    proxy_stream.write(&data).unwrap();

    let resp_header = TcpResponseHeader::read_from(&mut proxy_stream).unwrap();
    match resp_header.reply {
        Reply::Succeeded => {},
        _ => {
            panic!("Failed with error {:?}", resp_header.reply);
        }
    }

    io::copy(&mut proxy_stream, &mut stdout()).unwrap();
}

fn do_udp(matches: &Matches, svr_addr: &Address, proxy_addr: &SocketAddr) {
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

    let local_ip: IpAddr = matches.opt_str("b").expect("Require local address").parse().unwrap();
    let local_port: u16 = matches.opt_str("l").expect("Require local port").parse().unwrap();
    let local_addr = SocketAddr::new(local_ip, local_port);

    let mut udp_socket = UdpSocket::bind(local_addr).unwrap();

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

    let mut data = Vec::new();
    stdin().read_to_end(&mut data).unwrap();

    let mut bufw = Vec::new();
    let udp_header = UdpAssociateHeader::new(0, svr_addr.clone());
    udp_header.write_to(&mut bufw).unwrap();
    bufw.write(&data).unwrap();
    udp_socket.send_to(&bufw, proxy_real_addr).unwrap();

    let mut buf = [0; 0xffff];
    let (len, _) = udp_socket.recv_from(&mut buf).unwrap();

    let mut bufr = Cursor::new(&buf[..len]);
    let _ = UdpAssociateHeader::read_from(&mut bufr).unwrap();

    io::copy(&mut bufr, &mut stdout()).unwrap();
}

fn main() {

    let mut opts = Options::new();

    opts.optflag("h", "help", "Print help message");
    opts.optopt("s", "server-addr", "Server address", "");
    opts.optopt("p", "server-port", "Server port", "");
    opts.optopt("b", "local-addr", "Local address for binding", "");
    opts.optopt("l", "local-port", "Local port for binding", "");
    opts.optopt("x", "proxy-addr", "Proxy address", "");
    opts.optopt("o", "proxy-port", "Proxy port", "");
    opts.optopt("t", "protocol", "Protocol to use", "tcp");

    let matches = opts.parse(env::args().skip(1)).unwrap();

    if matches.opt_present("h") {
        println!("{}", opts.usage(&format!("Usage: {} [Options]", env::args().next().unwrap())));
        return;
    }

    let is_tcp = match &matches.opt_str("t").expect("Required to specify protocol")[..] {
        "tcp" => true,
        "udp" => false,
        _ => panic!("Unsupported protocol")
    };

    let ip: IpAddr = matches.opt_str("x").expect("Require proxy address").parse().unwrap();
    let port: u16 = matches.opt_str("o").expect("Require proxy port").parse().unwrap();
    let proxy_addr = SocketAddr::new(ip, port);

    let svr_port: u16 = matches.opt_str("p").expect("Require server port").parse().unwrap();
    let svr_addr = match matches.opt_str("s").expect("Require server address").parse::<IpAddr>() {
        Ok(ip) => Address::SocketAddress(SocketAddr::new(ip, svr_port)),
        Err(..) => Address::DomainNameAddress(matches.opt_str("s").unwrap(), svr_port),
    };

    if is_tcp {
        do_tcp(&matches, &svr_addr, &proxy_addr);
    } else {
        do_udp(&matches, &svr_addr, &proxy_addr);
    }
}
