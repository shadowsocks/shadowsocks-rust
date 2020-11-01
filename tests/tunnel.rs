#![cfg(feature = "local-tunnel")]

use std::str;

use tokio::{
    self,
    net::{TcpStream, UdpSocket},
    prelude::*,
    time::{self, Duration},
};

use shadowsocks::{
    config::{Config, ConfigType},
    relay::socks5::Address,
    run_local,
    run_server,
};

#[tokio::test]
async fn tcp_tunnel() {
    let _ = env_logger::try_init();

    let mut local_config = Config::load_from_str(
        r#"{
            "local_port": 9110,
            "local_address": "127.0.0.1",
            "server": "127.0.0.1",
            "server_port": 9120,
            "password": "password",
            "method": "aes-256-gcm"
        }"#,
        ConfigType::TunnelLocal,
    )
    .unwrap();

    local_config.forward = Some("www.example.com:80".parse::<Address>().unwrap());

    let server_config = Config::load_from_str(
        r#"{
            "server": "127.0.0.1",
            "server_port": 9120,
            "password": "password",
            "method": "aes-256-gcm"
        }"#,
        ConfigType::Server,
    )
    .unwrap();

    tokio::spawn(run_local(local_config));
    tokio::spawn(run_server(server_config));

    time::sleep(Duration::from_secs(1)).await;

    // Connect it directly, because it is now established a TCP tunnel with www.example.com
    let mut stream = TcpStream::connect("127.0.0.1:9110").await.unwrap();

    let req = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n";
    stream.write_all(req).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();

    println!("Got reply from server: {}", str::from_utf8(&buf).unwrap());

    let http_status = b"HTTP/1.0 200 OK\r\n";
    buf.starts_with(http_status);
}

#[tokio::test]
async fn udp_tunnel() {
    let _ = env_logger::try_init();

    let mut local_config = Config::load_from_str(
        r#"{
            "local_port": 9210,
            "local_address": "127.0.0.1",
            "server": "127.0.0.1",
            "server_port": 9220,
            "password": "password",
            "method": "aes-256-gcm",
            "mode": "tcp_and_udp"
        }"#,
        ConfigType::TunnelLocal,
    )
    .unwrap();

    local_config.forward = Some("127.0.0.1:9230".parse::<Address>().unwrap());

    let server_config = Config::load_from_str(
        r#"{
            "server": "127.0.0.1",
            "server_port": 9220,
            "password": "password",
            "method": "aes-256-gcm",
            "mode": "udp_only"
        }"#,
        ConfigType::Server,
    )
    .unwrap();

    tokio::spawn(run_local(local_config));
    tokio::spawn(run_server(server_config));

    // Start a UDP echo server
    tokio::spawn(async {
        let socket = UdpSocket::bind("127.0.0.1:9230").await.unwrap();

        let mut buf = vec![0u8; 65536];
        let (n, src) = socket.recv_from(&mut buf).await.unwrap();

        println!("UDP Echo server received packet, size: {}, src: {}", n, src);

        socket.send_to(&buf[..n], src).await.unwrap();
    });

    time::sleep(Duration::from_secs(1)).await;

    let payload = b"HELLO WORLD";

    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.send_to(payload, "127.0.0.1:9210").await.unwrap();

    let mut buf = vec![0u8; 65536];
    let n = socket.recv(&mut buf).await.unwrap();

    let recv_payload = &buf[..n];
    println!("Got reply from server: {}", str::from_utf8(recv_payload).unwrap());

    assert_eq!(recv_payload, payload);
}
