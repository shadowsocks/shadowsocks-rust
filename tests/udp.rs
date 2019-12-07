#![cfg_attr(clippy, allow(blacklisted_name))]

use std::{
    io::{self, Cursor},
    net::SocketAddr,
};

use bytes::{BufMut, BytesMut};
use log::debug;
use tokio::{
    prelude::*,
    time::{self, Duration},
};

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

const SERVER_ADDR: &str = "127.0.0.1:8093";
const LOCAL_ADDR: &str = "127.0.0.1:8291";

const UDP_ECHO_SERVER_ADDR: &str = "127.0.0.1:50403";
const UDP_LOCAL_ADDR: &str = "127.0.0.1:9011";

const PASSWORD: &str = "test-password";
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

fn start_server() {
    tokio::spawn(run_server(get_svr_config()));
}

fn start_local() {
    tokio::spawn(run_local(get_cli_config()));
}

fn start_udp_echo_server() {
    use tokio::net::UdpSocket;

    tokio::spawn(async {
        let mut l = UdpSocket::bind(UDP_ECHO_SERVER_ADDR).await.unwrap();

        debug!("UDP echo server started {}", UDP_ECHO_SERVER_ADDR);

        let mut buf = vec![0u8; 65536];
        let (amt, src) = l.recv_from(&mut buf).await.unwrap();

        debug!("UDP echo received {} bytes from {}", amt, src);

        l.send_to(&buf[..amt], &src).await.unwrap();

        debug!("UDP echo sent {} bytes to {}", amt, src);
    });
}

fn start_udp_request_holder(addr: Address) {
    tokio::spawn(async move {
        let (mut c, addr) = Socks5Client::udp_associate(addr, &get_client_addr()).await?;
        assert_eq!(addr, Address::SocketAddress(LOCAL_ADDR.parse().unwrap()));

        debug!("TCP sent UDP associate {} request", addr);

        // Holds it forever
        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await?;

        io::Result::Ok(())
    });
}

#[tokio::test]
async fn udp_relay() {
    use tokio::net::UdpSocket;

    let _ = env_logger::try_init();

    let remote_addr = Address::SocketAddress(UDP_ECHO_SERVER_ADDR.parse().unwrap());

    start_server();
    start_local();

    start_udp_echo_server();

    // Wait until all server starts
    time::delay_for(Duration::from_secs(1)).await;

    start_udp_request_holder(remote_addr.clone());

    let mut l = UdpSocket::bind(UDP_LOCAL_ADDR).await.unwrap();

    let header = UdpAssociateHeader::new(0, remote_addr);
    let mut buf = BytesMut::with_capacity(header.serialized_len());
    header.write_to_buf(&mut buf);

    let payload = b"HEllo WORld";

    buf.reserve(payload.len());
    buf.put_slice(payload);

    let local_addr = LOCAL_ADDR.parse::<SocketAddr>().unwrap();
    l.send_to(&buf[..], &local_addr).await.unwrap();

    let mut buf = vec![0u8; 65536];
    let (amt, _) = time::timeout(Duration::from_secs(5), l.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    println!("Received buf size={} {:?}", amt, &buf[..amt]);

    let mut cur = Cursor::new(buf[..amt].to_vec());
    let header = UdpAssociateHeader::read_from(&mut cur).await.unwrap();
    println!("{:?}", header);
    let header_len = cur.position() as usize;
    let buf = cur.into_inner();
    let buf = &buf[header_len..];

    assert_eq!(buf, payload);
}
