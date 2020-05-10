use std::net::{SocketAddr, ToSocketAddrs};

use tokio::{
    prelude::*,
    time::{self, Duration},
};

use shadowsocks::{
    config::{Config, ConfigType, Mode, ServerAddr, ServerConfig},
    crypto::CipherType,
    relay::{socks5::Address, tcprelay::client::Socks5Client},
    run_local,
    run_server,
};

pub struct Socks5TestServer {
    local_addr: SocketAddr,
    svr_config: Config,
    cli_config: Config,
}

impl Socks5TestServer {
    pub fn new<S, L>(svr_addr: S, local_addr: L, pwd: &str, method: CipherType, enable_udp: bool) -> Socks5TestServer
    where
        S: ToSocketAddrs,
        L: ToSocketAddrs,
    {
        let svr_addr = svr_addr.to_socket_addrs().unwrap().next().unwrap();
        let local_addr = local_addr.to_socket_addrs().unwrap().next().unwrap();

        Socks5TestServer {
            local_addr,
            svr_config: {
                let mut cfg = Config::new(ConfigType::Server);
                cfg.server = vec![ServerConfig::basic(svr_addr, pwd.to_owned(), method)];
                cfg.mode = if enable_udp { Mode::TcpAndUdp } else { Mode::TcpOnly };
                cfg
            },
            cli_config: {
                let mut cfg = Config::new(ConfigType::Socks5Local);
                cfg.local_addr = Some(ServerAddr::from(local_addr));
                cfg.server = vec![ServerConfig::basic(svr_addr, pwd.to_owned(), method)];
                cfg.mode = if enable_udp { Mode::TcpAndUdp } else { Mode::TcpOnly };
                cfg
            },
        }
    }

    pub fn client_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    pub async fn run(&self) {
        let svr_cfg = self.svr_config.clone();
        tokio::spawn(run_server(svr_cfg));

        let client_cfg = self.cli_config.clone();
        tokio::spawn(run_local(client_cfg));

        time::delay_for(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
async fn socks5_relay_stream() {
    let _ = env_logger::try_init();

    const SERVER_ADDR: &str = "127.0.0.1:8100";
    const LOCAL_ADDR: &str = "127.0.0.1:8200";

    const PASSWORD: &str = "test-password";
    const METHOD: CipherType = CipherType::Aes128Gcm;

    let svr = Socks5TestServer::new(SERVER_ADDR, LOCAL_ADDR, PASSWORD, METHOD, false);
    svr.run().await;

    let mut c = Socks5Client::connect(
        Address::DomainNameAddress("www.example.com".to_owned(), 80),
        svr.client_addr(),
    )
    .await
    .unwrap();

    let req = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n";
    c.write_all(req).await.unwrap();
    c.flush().await.unwrap();

    let mut buf = Vec::new();
    c.read_to_end(&mut buf).await.unwrap();

    println!("Got reply from server: {}", String::from_utf8(buf).unwrap());
}

#[tokio::test]
async fn socks5_relay_aead() {
    let _ = env_logger::try_init();

    const SERVER_ADDR: &str = "127.0.0.1:8110";
    const LOCAL_ADDR: &str = "127.0.0.1:8210";

    const PASSWORD: &str = "test-password";
    const METHOD: CipherType = CipherType::Aes256Gcm;

    let svr = Socks5TestServer::new(SERVER_ADDR, LOCAL_ADDR, PASSWORD, METHOD, false);
    svr.run().await;

    let mut c = Socks5Client::connect(
        Address::DomainNameAddress("www.example.com".to_owned(), 80),
        svr.client_addr(),
    )
    .await
    .unwrap();

    let req = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n";
    c.write_all(req).await.unwrap();
    c.flush().await.unwrap();

    let mut buf = Vec::new();
    c.read_to_end(&mut buf).await.unwrap();

    println!("Got reply from server: {}", String::from_utf8(buf).unwrap());
}
