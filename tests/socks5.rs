extern crate shadowsocks;
extern crate tokio_core;
extern crate tokio_io;
extern crate futures;
extern crate log;
extern crate env_logger;

use std::thread;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use tokio_core::reactor::Core;
use tokio_io::io::{read_to_end, write_all, flush};
use futures::Future;

use shadowsocks::relay::tcprelay::client::Socks5Client;
use shadowsocks::config::{Config, ServerConfig};
use shadowsocks::crypto::CipherType;
use shadowsocks::relay::socks5::Address;
use shadowsocks::{run_local, run_server};

pub struct Socks5TestServer {
    local_addr: SocketAddr,
    config: Config,
}

impl Socks5TestServer {
    pub fn new<S, L>(svr_addr: S,
                     local_addr: L,
                     pwd: &'static str,
                     method: CipherType,
                     enable_udp: bool)
                     -> Socks5TestServer
        where S: ToSocketAddrs,
              L: ToSocketAddrs
    {
        let svr_addr = svr_addr.to_socket_addrs().unwrap().next().unwrap();
        let local_addr = local_addr.to_socket_addrs().unwrap().next().unwrap();

        Socks5TestServer {
            local_addr: local_addr,
            config: {
                let mut cfg = Config::new();
                cfg.local = Some(local_addr);
                cfg.server = vec![ServerConfig::basic(svr_addr, pwd.to_owned(), method)];
                cfg.enable_udp = enable_udp;
                cfg
            },
        }
    }

    pub fn client_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    pub fn run(&self) {
        let svr_cfg = self.config.clone();
        thread::spawn(move || {
            run_server(svr_cfg).unwrap();
        });

        let client_cfg = self.config.clone();
        thread::spawn(move || {
            run_local(client_cfg).unwrap();
        });

        thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn socks5_relay_stream() {
    const SERVER_ADDR: &'static str = "127.0.0.1:8100";
    const LOCAL_ADDR: &'static str = "127.0.0.1:8200";

    const PASSWORD: &'static str = "test-password";
    const METHOD: CipherType = CipherType::Aes256Cfb;

    let svr = Socks5TestServer::new(SERVER_ADDR, LOCAL_ADDR, PASSWORD, METHOD, false);
    svr.run();

    let mut lp = Core::new().unwrap();
    let handle = lp.handle();

    let c = Socks5Client::connect(Address::DomainNameAddress("www.example.com".to_owned(), 80),
                                  *svr.client_addr(),
                                  handle);
    let fut = c.and_then(|c| {
        let req = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n";
        write_all(c, req.to_vec())
            .and_then(|(c, _)| flush(c))
            .and_then(|c| read_to_end(c, Vec::new()))
            .map(|(_, buf)| {
                println!("Got reply from server: {}", String::from_utf8(buf).unwrap());
            })
    });

    lp.run(fut).unwrap();
}

#[test]
fn socks5_relay_aead() {
    const SERVER_ADDR: &'static str = "127.0.0.1:8110";
    const LOCAL_ADDR: &'static str = "127.0.0.1:8210";

    const PASSWORD: &'static str = "test-password";
    const METHOD: CipherType = CipherType::Aes256Gcm;

    let svr = Socks5TestServer::new(SERVER_ADDR, LOCAL_ADDR, PASSWORD, METHOD, false);
    svr.run();

    let mut lp = Core::new().unwrap();
    let handle = lp.handle();

    let c = Socks5Client::connect(Address::DomainNameAddress("www.example.com".to_owned(), 80),
                                  *svr.client_addr(),
                                  handle);
    let fut = c.and_then(|c| {
        let req = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n";
        write_all(c, req.to_vec())
            .and_then(|(c, _)| flush(c))
            .and_then(|c| read_to_end(c, Vec::new()))
            .map(|(_, buf)| {
                println!("Got reply from server: {}", String::from_utf8(buf).unwrap());
            })
    });

    lp.run(fut).unwrap();
}
