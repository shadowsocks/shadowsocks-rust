//! Integration tests for hot-reloading the ACL file at runtime
//!
//! The ACL is only consulted when a connection is established, so swapping it must
//! change the routing of new connections without affecting the running server.

#![cfg(all(feature = "local", feature = "server"))]

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use tokio::{io::AsyncWriteExt, net::TcpListener, time};

use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType, LocalConfig, LocalInstanceConfig, ProtocolType, ServerInstanceConfig},
    local::{Server, socks::client::socks5::Socks5TcpClient},
    shadowsocks::{
        config::{ServerAddr, ServerConfig},
        crypto::CipherKind,
        relay::socks5::Address,
    },
};

const LOCAL_ADDR: &str = "127.0.0.1:8420";
// A closed port. Connections routed through the shadowsocks server will fail.
const DEAD_SERVER_ADDR: &str = "127.0.0.1:1";

const ACL_BYPASS_LOOPBACK: &str = "[bypass_all]\n[white_list]\n8.8.8.8\n";
const ACL_PROXY_LOOPBACK: &str = "[bypass_all]\n[white_list]\n127.0.0.1\n";

async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(..) => return,
            };
            let _ = sock.write_all(b"OK\n").await;
        }
    });

    addr
}

fn local_config_with_acl(acl_path: &std::path::Path, local_addr: SocketAddr) -> Config {
    let mut cfg = Config::new(ConfigType::Local);
    cfg.acl = Some(AccessControl::load_from_file(acl_path).unwrap());
    cfg.local = vec![LocalInstanceConfig::with_local_config(LocalConfig::new_with_addr(
        ServerAddr::from(local_addr),
        ProtocolType::Socks,
    ))];
    cfg.server = vec![ServerInstanceConfig::with_server_config(
        ServerConfig::new(
            DEAD_SERVER_ADDR.parse::<ServerAddr>().unwrap(),
            "test-password".to_owned(),
            CipherKind::AES_256_GCM,
        )
        .unwrap(),
    )];
    cfg
}

#[tokio::test]
async fn acl_hot_reload_changes_new_connection_routing() {
    let _ = env_logger::try_init();

    let target_addr = spawn_echo_server().await;
    let local_addr: SocketAddr = LOCAL_ADDR.parse().unwrap();

    let acl_path: PathBuf = std::env::temp_dir().join(format!("shadowsocks-acl-reload-it-{}", std::process::id()));
    std::fs::write(&acl_path, ACL_BYPASS_LOOPBACK).unwrap();

    let config = local_config_with_acl(&acl_path, local_addr);
    let server = Server::new(config).await.unwrap();
    let acl_reload_context = server.acl_reload_context();
    tokio::spawn(server.run());

    // No shadowsocks server is running at all: proxied connections fail because they
    // cannot reach the configured server address, while bypassed connections connect
    // to the local echo server directly.

    time::sleep(Duration::from_secs(1)).await;

    // The loopback target is not in white_list, so it is bypassed and reaches the echo server
    let mut c = Socks5TcpClient::connect(Address::SocketAddress(target_addr), &local_addr)
        .await
        .expect("bypassed connection should reach the target");
    c.shutdown().await.unwrap();

    // Loopback moves into white_list: the target is now proxied, and the proxy is unreachable
    std::fs::write(&acl_path, ACL_PROXY_LOOPBACK).unwrap();
    acl_reload_context.reload_acl().await.unwrap();

    let result = Socks5TcpClient::connect(Address::SocketAddress(target_addr), &local_addr).await;
    assert!(
        result.is_err(),
        "proxied connection through the dead server should fail"
    );

    // Reload back: new connections are bypassed again
    std::fs::write(&acl_path, ACL_BYPASS_LOOPBACK).unwrap();
    acl_reload_context.reload_acl().await.unwrap();

    let mut c = Socks5TcpClient::connect(Address::SocketAddress(target_addr), &local_addr)
        .await
        .expect("connection should be bypassed again after reloading");
    c.shutdown().await.unwrap();

    let _ = std::fs::remove_file(&acl_path);
}
