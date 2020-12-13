#![cfg(feature = "local-http")]

use std::time::Duration;

use tokio::{net::TcpStream, prelude::*, time};

use shadowsocks_service::{
    config::{Config, ConfigType, ProtocolType},
    run_local,
    run_server,
};

#[tokio::test]
async fn http_proxy() {
    let _ = env_logger::try_init();

    let mut local_config = Config::load_from_str(
        r#"{
            "local_port": 5110,
            "local_address": "127.0.0.1",
            "server": "127.0.0.1",
            "server_port": 5120,
            "password": "password",
            "method": "aes-256-gcm"
        }"#,
        ConfigType::Local,
    )
    .unwrap();
    local_config.local_protocol = ProtocolType::Http;

    let server_config = Config::load_from_str(
        r#"{
            "server": "127.0.0.1",
            "server_port": 5120,
            "password": "password",
            "method": "aes-256-gcm"
        }"#,
        ConfigType::Server,
    )
    .unwrap();

    tokio::spawn(run_local(local_config));
    tokio::spawn(run_server(server_config));

    time::sleep(Duration::from_secs(1)).await;

    {
        let mut c = TcpStream::connect("127.0.0.1:5110").await.unwrap();
        c.write_all(b"GET http://www.example.com/ HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n")
            .await
            .unwrap();
        c.flush().await.unwrap();

        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();

        assert!(buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
    }

    {
        let mut c = TcpStream::connect("127.0.0.1:5110").await.unwrap();
        c.write_all(b"CONNECT http://www.example.com/ HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        c.flush().await.unwrap();

        c.write_all(b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n")
            .await
            .unwrap();
        c.flush().await.unwrap();

        let mut buf = Vec::new();
        c.read_to_end(&mut buf).await.unwrap();

        assert!(buf.starts_with(b"HTTP/1.0 200 OK\r\n"));
    }
}
