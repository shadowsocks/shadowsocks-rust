use env_logger;
use tokio;
use tokio::net::TcpStream;
use tokio::prelude::*;
use tokio::time::{self, Duration};

use shadowsocks::config::{Config, ConfigType};
use shadowsocks::relay::socks5::Address;
use shadowsocks::{run_local, run_server};

#[tokio::test(threaded_scheduler)]
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
        ConfigType::Local,
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

    time::delay_for(Duration::from_secs(1)).await;

    // Connect it directly, because it is now established a TCP tunnel with www.example.com
    let mut stream = TcpStream::connect("127.0.0.1:9110").await.unwrap();

    let req = b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n";
    stream.write_all(req).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();

    println!("Got reply from server: {}", String::from_utf8(buf).unwrap());
}
