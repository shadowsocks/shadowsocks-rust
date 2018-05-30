extern crate dns_parser;
extern crate env_logger;
extern crate rand;
extern crate shadowsocks;
extern crate tokio;
#[macro_use]
extern crate log;

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use dns_parser::{Builder, Packet, QueryClass, QueryType};
use shadowsocks::config::{Config, ConfigType};
use shadowsocks::{run_dns, run_server};
use tokio::runtime::current_thread::Runtime;

const CONFIG: &'static str = r#"{
        "server": "127.0.0.1",
        "server_port": 8988,
        "local_port": 5030,
        "local_address": "127.0.0.1",
        "password": "abc",
        "timeout": 20,
        "method": "aes-256-gcm",
        "enable_udp": true
    }"#;

#[test]
fn dns_relay() {
    let _ = env_logger::try_init();

    let server_cfg = Config::load_from_str(CONFIG, ConfigType::Server).unwrap();
    let dns_cfg = Config::load_from_str(CONFIG, ConfigType::Local).unwrap();

    thread::spawn(move || {
                      let mut runtime = Runtime::new().expect("Failed to create Runtime");
                      runtime.block_on(run_server(server_cfg)).unwrap();
                  });

    thread::spawn(move || {
                      let mut runtime = Runtime::new().expect("Failed to create Runtime");
                      runtime.block_on(run_dns(dns_cfg)).unwrap();
                  });

    thread::sleep(Duration::from_secs(1));

    let dns_addr = "127.0.0.1:5030".parse::<SocketAddr>().unwrap();
    let local_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    let local = UdpSocket::bind(&local_addr).unwrap();
    local.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    local.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    const LOOP_ROUND: usize = 10;

    let mut sent_id = HashSet::<u16, _>::with_capacity(LOOP_ROUND);
    for _ in 0..LOOP_ROUND {
        let mut id = rand::random::<u16>();
        while let Some(..) = sent_id.get(&id) {
            id = rand::random::<u16>();
        }

        sent_id.insert(id);

        let mut builder = Builder::new_query(id, false);
        builder.add_question("www.example.com", QueryType::A, QueryClass::IN);

        let payload = builder.build().unwrap();

        local.send_to(&payload, &dns_addr).unwrap();

        trace!("DNS SENT {:?}", payload);

        let mut buf = [0u8; 65535];
        let (len, _) = local.recv_from(&mut buf).unwrap();

        let packet = Packet::parse(&buf[..len]).unwrap();

        trace!("DNS GOT {:?}", packet);
        assert_eq!(packet.header.id, id);
    }
}
