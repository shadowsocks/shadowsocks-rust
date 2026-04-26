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

#[tokio::test]
async fn tcp_dynamic_tunnel() {
    let _ = env_logger::try_init();

    let (local_port, server_port) = random_local_tcp_port_pair();
    let local_config = Config::load_from_str(
        &format!(
            r#"{{
            "locals": [
                {{
                    "local_port": {local_port},
                    "local_address": "127.0.0.1",
                    "protocol": "tunnel"
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

    // Dynamic tunnel: prepend ATYP+DOMAIN+PORT header on the TCP stream.
    let mut stream = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();

    const HOST: &[u8] = b"detectportal.firefox.com";
    let mut header = Vec::with_capacity(2 + HOST.len() + 2);
    header.push(0x03); // ATYP = DOMAIN
    header.push(HOST.len() as u8);
    header.extend_from_slice(HOST);
    header.extend_from_slice(&80u16.to_be_bytes());
    stream.write_all(&header).await.unwrap();

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
async fn udp_dynamic_tunnel() {
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
                    "protocol": "tunnel"
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

    // Malformed header (ATYP=DOMAIN, LEN=3, "abc", missing 2-byte PORT) must
    // be rejected without taking down the dynamic UDP listener.
    let malformed: &[u8] = &[0x03, 0x03, b'a', b'b', b'c'];
    socket.send_to(malformed, ("127.0.0.1", local_port)).await.unwrap();

    // Dynamic tunnel: prepend ATYP+IPv4+PORT header on each UDP packet.
    let port_be = echo_server_port.to_be_bytes();
    let mut packet = Vec::with_capacity(7 + MESSAGE.len());
    packet.extend_from_slice(&[0x01, 127, 0, 0, 1, port_be[0], port_be[1]]);
    packet.extend_from_slice(MESSAGE);

    socket.send_to(&packet, ("127.0.0.1", local_port)).await.unwrap();

    let mut buf = vec![0u8; 65536];
    let n = socket.recv(&mut buf).await.unwrap();

    let recv_payload = &buf[..n];
    println!("Got reply from server: {:?}", ByteStr::new(recv_payload));

    // Response is prefixed with the same ATYP+ADDR+PORT header (7 bytes for IPv4).
    assert_eq!(recv_payload[0], 0x01);
    assert_eq!(&recv_payload[7..], MESSAGE);
}
