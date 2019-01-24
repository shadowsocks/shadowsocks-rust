#![cfg_attr(clippy, allow(blacklisted_name))]

use std::{
    io::Cursor,
    net::SocketAddr,
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use futures::Future;
use tokio::runtime::current_thread::Runtime;
use tokio_io::io::read_to_end;

use shadowsocks::{
    config::{Config, ConfigType, Mode, ServerConfig},
    crypto::CipherType,
    relay::{
        socks5::{Address, UdpAssociateHeader},
        tcprelay::client::Socks5Client,
    },
    run_local,
    run_server,
};

const SERVER_ADDR: &'static str = "127.0.0.1:8093";
const LOCAL_ADDR: &'static str = "127.0.0.1:8291";

const UDP_ECHO_SERVER_ADDR: &'static str = "127.0.0.1:50403";
const UDP_LOCAL_ADDR: &'static str = "127.0.0.1:9011";

const PASSWORD: &'static str = "test-password";
const METHOD: CipherType = CipherType::Aes128Cfb;

fn get_svr_config() -> Config {
    let mut cfg = Config::new(ConfigType::Server);
    cfg.server = vec![ServerConfig::basic(
        SERVER_ADDR.parse().unwrap(),
        PASSWORD.to_owned(),
        METHOD,
    )];
    cfg.mode = Mode::UdpOnly;
    cfg
}

fn get_cli_config() -> Config {
    let mut cfg = Config::new(ConfigType::Local);
    cfg.local = Some(LOCAL_ADDR.parse().unwrap());
    cfg.server = vec![ServerConfig::basic(
        SERVER_ADDR.parse().unwrap(),
        PASSWORD.to_owned(),
        METHOD,
    )];
    cfg.mode = Mode::UdpOnly;
    cfg
}

fn get_client_addr() -> SocketAddr {
    LOCAL_ADDR.parse().unwrap()
}

fn start_server(bar: Arc<Barrier>) {
    thread::spawn(move || {
        let mut runtime = Runtime::new().expect("Failed to create Runtime");

        let fut = run_server(get_svr_config());
        bar.wait();
        runtime.block_on(fut).expect("Failed to run Server");
    });
}

fn start_local(bar: Arc<Barrier>) {
    thread::spawn(move || {
        let mut runtime = Runtime::new().expect("Failed to create Runtime");

        let fut = run_local(get_cli_config());
        bar.wait();
        runtime.block_on(fut).expect("Failed to run Local");
    });
}

fn start_udp_echo_server(bar: Arc<Barrier>) {
    use std::net::UdpSocket;

    thread::spawn(move || {
        let l = UdpSocket::bind(UDP_ECHO_SERVER_ADDR).unwrap();

        bar.wait();

        let mut buf = [0u8; 65536];
        let (amt, src) = l.recv_from(&mut buf).unwrap();

        l.send_to(&buf[..amt], &src).unwrap();
    });
}

fn start_udp_request_holder(bar: Arc<Barrier>, addr: Address) {
    thread::spawn(move || {
        let mut runtime = Runtime::new().expect("Failed to create Runtime");

        let c = Socks5Client::udp_associate(addr, get_client_addr());
        let fut = c.and_then(|(c, addr)| {
            assert_eq!(addr, Address::SocketAddress(LOCAL_ADDR.parse().unwrap()));

            // Holds it forever
            read_to_end(c, Vec::new()).map(|_| ())
        });

        bar.wait();

        runtime.block_on(fut).expect("Failed to run UDP socks5 client");
    });
}

#[test]
fn udp_relay() {
    use std::net::UdpSocket;

    let _ = env_logger::try_init();

    let remote_addr = Address::SocketAddress(UDP_ECHO_SERVER_ADDR.parse().unwrap());

    let bar = Arc::new(Barrier::new(4));

    start_server(bar.clone());
    start_local(bar.clone());

    start_udp_echo_server(bar.clone());

    bar.wait();

    // Wait until all server starts
    thread::sleep(Duration::from_secs(1));

    let bar = Arc::new(Barrier::new(2));

    start_udp_request_holder(bar.clone(), remote_addr.clone());

    bar.wait();

    let l = UdpSocket::bind(UDP_LOCAL_ADDR).unwrap();
    l.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    l.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let header = UdpAssociateHeader::new(0, remote_addr);
    let mut buf = BytesMut::with_capacity(header.len());
    header.write_to_buf(&mut buf);

    let payload = b"HEllo WORld";

    buf.reserve(payload.len());
    buf.put_slice(payload);

    let local_addr = LOCAL_ADDR.parse::<SocketAddr>().unwrap();
    l.send_to(&buf[..], &local_addr).unwrap();

    let mut buf = [0u8; 65536];
    let (amt, _) = l.recv_from(&mut buf).unwrap();
    println!("Received buf size={} {:?}", amt, &buf[..amt]);

    let cur = Cursor::new(buf[..amt].to_vec());
    let (cur, header) = UdpAssociateHeader::read_from(cur).wait().expect("Invalid UDP header");
    println!("{:?}", header);
    let header_len = cur.position() as usize;
    let buf = cur.into_inner();
    let buf = &buf[header_len..];

    assert_eq!(buf, payload);
}
