#![cfg(all(feature = "local-tunnel", feature = "server"))]

use byte_string::ByteStr;
use log::debug;
use tokio::{
    self,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, UdpSocket},
    time::{self, Duration},
};

use shadowsocks_service::{
    config::{Config, ConfigType},
    run_local, run_server,
};

fn random_local_tcp_port_pair() -> (u16, u16) {
    let listener1 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port1 = listener1.local_addr().unwrap().port();

    let listener2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port2 = listener2.local_addr().unwrap().port();

    (port1, port2)
}

#[tokio::test]
async fn tcp_tunnel() {
    let _ = env_logger::try_init();

    let (local_port, server_port) = random_local_tcp_port_pair();
    let local_config = Config::load_from_str(
        &format!(
            r#"{{
            "locals": [
                {{
                    "local_port": {local_port},
                    "local_address": "127.0.0.1",
                    "protocol": "tunnel",
                    "forward_address": "detectportal.firefox.com",
                    "forward_port": 80
                }}
            ],
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "password",
            "method": "aes-256-gcm"
        }}"#
        ),
        ConfigType::Local,
    )
    .unwrap();

    let server_config = Config::load_from_str(
        &format!(
            r#"{{
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "password",
            "method": "aes-256-gcm"
        }}"#
        ),
        ConfigType::Server,
    )
    .unwrap();

    tokio::spawn(run_local(local_config));
    tokio::spawn(run_server(server_config));

    time::sleep(Duration::from_secs(5)).await;

    // Connect it directly, because it is now established a TCP tunnel with detectportal.firefox.com
    let mut stream = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();

    let req = b"GET /success.txt HTTP/1.0\r\nHost: detectportal.firefox.com\r\nAccept: */*\r\n\r\n";
    stream.write_all(req).await.unwrap();
    stream.flush().await.unwrap();

    let mut r = BufReader::new(stream);

    let mut buf = Vec::new();
    r.read_until(b'\n', &mut buf).await.unwrap();

    let http_status = b"HTTP/1.0 200 OK\r\n";
    assert!(buf.starts_with(http_status));
}

#[tokio::test]
async fn udp_tunnel() {
    let _ = env_logger::try_init();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_local_addr = socket.local_addr().unwrap();
    let echo_server_port = socket_local_addr.port();

    // A UDP echo server
    tokio::spawn(async move {
        debug!("UDP echo server listening on {socket_local_addr}");

        let mut buffer = [0u8; 65536];
        loop {
            let (n, peer_addr) = socket.recv_from(&mut buffer).await.unwrap();
            debug!("UDP echo server received {} bytes from {}, echoing", n, peer_addr);
            socket.send_to(&buffer[..n], peer_addr).await.unwrap();
        }
    });

    time::sleep(Duration::from_secs(1)).await;

    let (local_port, server_port) = random_local_tcp_port_pair();
    let local_config = Config::load_from_str(
        &format!(
            r#"{{
            "locals": [
                {{
                    "local_port": {local_port},
                    "local_address": "127.0.0.1",
                    "protocol": "tunnel",
                    "forward_address": "127.0.0.1",
                    "forward_port": {echo_server_port}
                }}
            ],
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "password",
            "method": "aes-256-gcm",
            "mode": "tcp_and_udp"
        }}"#
        ),
        ConfigType::Local,
    )
    .unwrap();

    let server_config = Config::load_from_str(
        &format!(
            r#"{{
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "password",
            "method": "aes-256-gcm",
            "mode": "udp_only"
        }}"#
        ),
        ConfigType::Server,
    )
    .unwrap();

    tokio::spawn(run_local(local_config));
    tokio::spawn(run_server(server_config));

    time::sleep(Duration::from_secs(5)).await;

    const MESSAGE: &[u8] = b"hello shadowsocks";

    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.send_to(MESSAGE, ("127.0.0.1", local_port)).await.unwrap();

    let mut buf = vec![0u8; 65536];
    let n = socket.recv(&mut buf).await.unwrap();

    let recv_payload = &buf[..n];
    println!("Got reply from server: {:?}", ByteStr::new(recv_payload));

    assert_eq!(MESSAGE, recv_payload);
}
