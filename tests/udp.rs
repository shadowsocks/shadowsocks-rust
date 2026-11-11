#![cfg(all(feature = "local", feature = "server"))]

use std::net::SocketAddr;

use log::debug;
use tokio::time::{self, Duration};

use shadowsocks_service::{
    config::{Config, ConfigType, LocalConfig, LocalInstanceConfig, ProtocolType, ServerInstanceConfig},
    local::socks::client::socks5::Socks5UdpClient,
    run_local, run_server,
    shadowsocks::{ServerConfig, config::Mode, crypto::CipherKind, relay::socks5::Address},
};

const SERVER_ADDR: &str = "127.0.0.1:8093";
const LOCAL_ADDR: &str = "127.0.0.1:8291";

const UDP_ECHO_SERVER_ADDR: &str = "127.0.0.1:50403";

const PASSWORD: &str = "test-password";
const METHOD: CipherKind = CipherKind::AES_128_GCM;

fn get_svr_config() -> Config {
    let mut cfg = Config::new(ConfigType::Server);
    cfg.server = vec![ServerInstanceConfig::with_server_config(
        ServerConfig::new(SERVER_ADDR.parse::<SocketAddr>().unwrap(), PASSWORD.to_owned(), METHOD).unwrap(),
    )];
    cfg.server[0].config.set_mode(Mode::TcpAndUdp);
    cfg
}

fn get_cli_config() -> Config {
    let mut cfg = Config::new(ConfigType::Local);
    cfg.local = vec![LocalInstanceConfig::with_local_config(LocalConfig::new_with_addr(
        LOCAL_ADDR.parse().unwrap(),
        ProtocolType::Socks,
    ))];
    cfg.local[0].config.mode = Mode::TcpAndUdp;
    cfg.server = vec![ServerInstanceConfig::with_server_config(
        ServerConfig::new(SERVER_ADDR.parse::<SocketAddr>().unwrap(), PASSWORD.to_owned(), METHOD).unwrap(),
    )];
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
        let l = UdpSocket::bind(UDP_ECHO_SERVER_ADDR).await.unwrap();

        debug!("UDP echo server started {}", UDP_ECHO_SERVER_ADDR);

        let mut buf = vec![0u8; 65536];
        let (amt, src) = l.recv_from(&mut buf).await.unwrap();

        debug!("UDP echo received {} bytes from {}", amt, src);

        l.send_to(&buf[..amt], &src).await.unwrap();

        debug!("UDP echo sent {} bytes to {}", amt, src);
    });
}

#[tokio::test]
async fn udp_relay() {
    let _ = env_logger::try_init();

    let remote_addr = Address::SocketAddress(UDP_ECHO_SERVER_ADDR.parse().unwrap());

    start_server();
    start_local();

    start_udp_echo_server();

    // Wait until all server starts
    time::sleep(Duration::from_secs(1)).await;

    let mut l = Socks5UdpClient::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    l.associate(&get_client_addr()).await.unwrap();

    let payload = b"HEllo WORld";
    l.send_to(0, payload, &remote_addr).await.unwrap();

    let mut buf = vec![0u8; 65536];
    let (amt, _, recv_addr) = time::timeout(Duration::from_secs(5), l.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    println!("Received {} buf size={} {:?}", recv_addr, amt, &buf[..amt]);

    assert_eq!(recv_addr, remote_addr);
    assert_eq!(&buf[..amt], payload);
}

#[tokio::test]
async fn udp_relay_requires_socks5_auth_association() {
    use shadowsocks_service::{
        local::socks::{client::socks5::Socks5TcpClient, config::Socks5AuthConfig},
        net::Socks5Auth,
        shadowsocks::relay::socks5::UdpAssociateHeader,
    };
    use tokio::net::UdpSocket;

    let _ = env_logger::try_init();

    const SERVER_ADDR: &str = "127.0.0.1:8094";
    const LOCAL_ADDR: &str = "127.0.0.1:8292";
    const ECHO_ADDR: &str = "127.0.0.1:50404";

    let mut svr_cfg = get_svr_config();
    svr_cfg.server[0]
        .config
        .set_addr(SERVER_ADDR.parse::<SocketAddr>().unwrap());
    tokio::spawn(run_server(svr_cfg));

    let mut cli_cfg = get_cli_config();
    cli_cfg.local[0].config.addr = Some(LOCAL_ADDR.parse::<SocketAddr>().unwrap().into());
    cli_cfg.server[0]
        .config
        .set_addr(SERVER_ADDR.parse::<SocketAddr>().unwrap());
    let mut auth = Socks5AuthConfig::new();
    auth.passwd.add_user("user", "pass");
    cli_cfg.local[0].config.socks5_auth = auth;
    tokio::spawn(run_local(cli_cfg));

    tokio::spawn(async {
        let l = UdpSocket::bind(ECHO_ADDR).await.unwrap();
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, src) = l.recv_from(&mut buf).await.unwrap();
            l.send_to(&buf[..n], src).await.unwrap();
        }
    });

    time::sleep(Duration::from_secs(1)).await;

    // Sends one datagram from `socket` through the relay and reports whether the echo came back
    async fn echoed(socket: &UdpSocket, payload: &[u8]) -> bool {
        let mut pkt = Vec::new();
        UdpAssociateHeader::new(0, Address::SocketAddress(ECHO_ADDR.parse().unwrap())).write_to_buf(&mut pkt);
        pkt.extend_from_slice(payload);
        socket.send_to(&pkt, LOCAL_ADDR).await.unwrap();

        let mut buf = vec![0u8; 65536];
        match time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await {
            Ok(n) => buf[..n.unwrap()].ends_with(payload),
            Err(..) => false,
        }
    }

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(!echoed(&socket, b"no association").await);

    let auth = Socks5Auth::username_password("user", "pass");
    let (control, _) = Socks5TcpClient::udp_associate_with_auth(socket.local_addr().unwrap(), LOCAL_ADDR, &auth)
        .await
        .unwrap();
    assert!(echoed(&socket, b"associated").await);

    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(!echoed(&other, b"other port").await);

    drop(control);
    time::sleep(Duration::from_millis(200)).await;
    assert!(!echoed(&socket, b"control closed").await);
}
