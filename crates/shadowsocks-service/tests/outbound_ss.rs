#![cfg(feature = "aead-cipher")]

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use shadowsocks_service::{
    config::{OutboundProxy, ShadowsocksHop},
    net::{OutboundProxyClient, TcpDialer},
    shadowsocks::{
        ProxyListener,
        config::{Mode, ServerConfig, ServerType},
        context::{Context, SharedContext},
        crypto::CipherKind,
        net::{ConnectOpts, TcpStream as ShadowTcpStream},
        plugin::PluginConfig,
        relay::socks5::Address,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

struct DirectDialer {
    context: SharedContext,
}

impl TcpDialer for DirectDialer {
    async fn dial(&self, addr: &Address) -> io::Result<ShadowTcpStream> {
        ShadowTcpStream::connect_remote_with_opts(&self.context, addr, &ConnectOpts::default()).await
    }
}

async fn make_ss_listener(password: &str) -> (ProxyListener, ServerConfig) {
    let bind_config = ServerConfig::new(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        password,
        CipherKind::AES_128_GCM,
    )
    .unwrap();
    let listener = ProxyListener::bind(Context::new_shared(ServerType::Server), &bind_config)
        .await
        .unwrap();
    let client_config = ServerConfig::new(listener.local_addr().unwrap(), password, CipherKind::AES_128_GCM).unwrap();
    (listener, client_config)
}

fn spawn_ss_relay(listener: ProxyListener) {
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(target) = inbound.handshake().await else {
                    return;
                };
                let mut outbound = match target {
                    Address::SocketAddress(addr) => TcpStream::connect(addr).await.unwrap(),
                    Address::DomainNameAddress(host, port) => TcpStream::connect((host, port)).await.unwrap(),
                };
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                    .await
                    .unwrap();
            });
        }
    });
}

fn spawn_ss_relay_reporting_targets(listener: ProxyListener, targets: mpsc::UnboundedSender<Address>) {
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let targets = targets.clone();
            tokio::spawn(async move {
                let Ok(target) = inbound.handshake().await else {
                    return;
                };
                let _ = targets.send(target.clone());
                let mut outbound = match target {
                    Address::SocketAddress(addr) => TcpStream::connect(addr).await.unwrap(),
                    Address::DomainNameAddress(host, port) => TcpStream::connect((host, port)).await.unwrap(),
                };
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                    .await
                    .unwrap();
            });
        }
    });
}

#[tokio::test]
async fn sslocal_main_server_is_first_hop_and_outbound_proxy_is_landing() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });

    let (main_listener, main_config) = make_ss_listener("main-first-hop-password").await;
    let (landing_listener, landing_config) = make_ss_listener("landing-password").await;
    let landing_addr = landing_listener.local_addr().unwrap();
    let (main_targets_tx, mut main_targets_rx) = mpsc::unbounded_channel();
    let (landing_targets_tx, mut landing_targets_rx) = mpsc::unbounded_channel();
    spawn_ss_relay_reporting_targets(main_listener, main_targets_tx);
    spawn_ss_relay_reporting_targets(landing_listener, landing_targets_tx);

    let landing_proxy = OutboundProxy::from_url(&landing_config.to_url()).unwrap();
    let client = OutboundProxyClient::try_from_config_after_main_server(&[landing_proxy]).unwrap();
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let mut stream = client
        .connect_tcp_with_initial_shadowsocks(context, &dialer, &main_config, &Address::from(echo_addr))
        .await
        .unwrap();

    const MESSAGE: &[u8] = b"main first, outbound landing";
    stream.write_all(MESSAGE).await.unwrap();
    assert_eq!(main_targets_rx.recv().await, Some(Address::from(landing_addr)));
    assert_eq!(landing_targets_rx.recv().await, Some(Address::from(echo_addr)));
    let mut echoed = vec![0u8; MESSAGE.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, MESSAGE);
}

#[tokio::test]
async fn tcp_echo_through_two_shadowsocks_outbound_hops() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });

    let (first_listener, first_config) = make_ss_listener("first-hop-password").await;
    let (second_listener, second_config) = make_ss_listener("second-hop-password").await;
    spawn_ss_relay(first_listener);
    spawn_ss_relay(second_listener);

    let proxies = [first_config, second_config]
        .into_iter()
        .map(|config| OutboundProxy::from_url(&config.to_url()).unwrap())
        .collect::<Vec<_>>();
    let client = OutboundProxyClient::try_from_config(&proxies).unwrap();
    assert!(!client.supports_udp());

    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let mut stream = client
        .connect_tcp(context, &dialer, &Address::from(echo_addr))
        .await
        .unwrap();

    const MESSAGE: &[u8] = b"two encrypted outbound hops";
    stream.write_all(MESSAGE).await.unwrap();
    let mut echoed = vec![0u8; MESSAGE.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, MESSAGE);
}

#[tokio::test]
async fn tcp_echo_through_first_shadowsocks_hop_plugin() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });

    let (listener, mut config) = make_ss_listener("plugin-hop-password").await;
    spawn_ss_relay(listener);
    config.set_plugin(PluginConfig {
        plugin: std::env::current_exe().unwrap().to_string_lossy().into_owned(),
        plugin_opts: Some("mock-options".to_owned()),
        plugin_args: vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "mock_sip003_plugin_process".to_owned(),
            "--nocapture".to_owned(),
        ],
        plugin_mode: Mode::TcpOnly,
    });

    let client = OutboundProxyClient::try_from_config(&[OutboundProxy::Ss(Box::new(ShadowsocksHop {
        svr_cfg: config,
        tag: Some("mock-plugin".to_owned()),
    }))])
    .unwrap();
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let mut stream = client
        .connect_tcp(context, &dialer, &Address::from(echo_addr))
        .await
        .unwrap();

    const MESSAGE: &[u8] = b"first hop plugin";
    stream.write_all(MESSAGE).await.unwrap();
    let mut echoed = vec![0u8; MESSAGE.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, MESSAGE);
}

#[tokio::test]
async fn first_hop_plugin_start_failure_is_throttled_and_retried() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.unwrap();
        }
    });

    let (listener, mut config) = make_ss_listener("late-plugin-password").await;
    spawn_ss_relay(listener);
    config.set_plugin(PluginConfig {
        plugin: std::env::current_exe().unwrap().to_string_lossy().into_owned(),
        plugin_opts: Some("mock-options".to_owned()),
        plugin_args: vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "mock_sip003_plugin_starts_late".to_owned(),
            "--nocapture".to_owned(),
        ],
        plugin_mode: Mode::TcpOnly,
    });

    let client = OutboundProxyClient::try_from_config(&[OutboundProxy::Ss(Box::new(ShadowsocksHop {
        svr_cfg: config,
        tag: Some("mock-plugin-failure".to_owned()),
    }))])
    .unwrap();
    assert!(client.contains_shadowsocks_hop());
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };
    let target = Address::from(echo_addr);

    let first = tokio::time::timeout(
        Duration::from_secs(5),
        client.connect_tcp(context.clone(), &dialer, &target),
    )
    .await
    .expect("initial plugin readiness check exceeded its timeout");
    let first_error = match first {
        Ok(_) => panic!("plugin unexpectedly accepted a connection before its delayed start"),
        Err(err) => err,
    };
    assert_eq!(first_error.kind(), io::ErrorKind::TimedOut);

    let second = tokio::time::timeout(
        Duration::from_millis(500),
        client.connect_tcp(context.clone(), &dialer, &target),
    )
    .await
    .expect("throttled plugin startup failure did not fail fast");
    let second_error = match second {
        Ok(_) => panic!("plugin unexpectedly accepted a connection before its delayed start"),
        Err(err) => err,
    };
    assert_eq!(second_error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(second_error.to_string(), first_error.to_string());

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let mut stream = tokio::time::timeout(Duration::from_secs(2), client.connect_tcp(context, &dialer, &target))
        .await
        .expect("plugin readiness retry timed out")
        .expect("late-starting plugin did not recover");

    const MESSAGE: &[u8] = b"late plugin recovery";
    stream.write_all(MESSAGE).await.unwrap();
    let mut echoed = vec![0u8; MESSAGE.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, MESSAGE);
}

#[test]
fn plugin_on_non_first_shadowsocks_hop_is_rejected() {
    let first = ServerConfig::new(
        "127.0.0.1:10001".parse::<SocketAddr>().unwrap(),
        "first",
        CipherKind::AES_128_GCM,
    )
    .unwrap();
    let mut second = ServerConfig::new(
        "127.0.0.1:10002".parse::<SocketAddr>().unwrap(),
        "second",
        CipherKind::AES_128_GCM,
    )
    .unwrap();
    second.set_plugin(PluginConfig {
        plugin: "mock-plugin".to_owned(),
        plugin_opts: None,
        plugin_args: Vec::new(),
        plugin_mode: Mode::TcpOnly,
    });

    let proxies = vec![
        OutboundProxy::Ss(Box::new(ShadowsocksHop {
            svr_cfg: first,
            tag: None,
        })),
        OutboundProxy::Ss(Box::new(ShadowsocksHop {
            svr_cfg: second,
            tag: None,
        })),
    ];
    let err = OutboundProxyClient::try_from_config(&proxies).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("non-first ss outbound proxy hop"));
}

#[test]
fn sslocal_outbound_proxy_plugin_is_rejected_as_non_first_hop() {
    let mut landing = ServerConfig::new(
        "127.0.0.1:10004".parse::<SocketAddr>().unwrap(),
        "landing",
        CipherKind::AES_128_GCM,
    )
    .unwrap();
    landing.set_plugin(PluginConfig {
        plugin: "mock-plugin".to_owned(),
        plugin_opts: None,
        plugin_args: Vec::new(),
        plugin_mode: Mode::TcpOnly,
    });

    let err = OutboundProxyClient::try_from_config_after_main_server(&[OutboundProxy::Ss(Box::new(ShadowsocksHop {
        svr_cfg: landing,
        tag: None,
    }))])
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("non-first ss outbound proxy hop"));
}

#[tokio::test]
async fn udp_rejects_chain_containing_shadowsocks_hop() {
    let config = ServerConfig::new(
        "127.0.0.1:10003".parse::<SocketAddr>().unwrap(),
        "udp",
        CipherKind::AES_128_GCM,
    )
    .unwrap();
    let client = OutboundProxyClient::try_from_config(&[OutboundProxy::Ss(Box::new(ShadowsocksHop {
        svr_cfg: config,
        tag: None,
    }))])
    .unwrap();
    let context = Context::new_shared(ServerType::Local);
    let dialer = DirectDialer {
        context: context.clone(),
    };

    let result = client
        .associate_udp(
            &context,
            &dialer,
            &ConnectOpts::default(),
            Address::from("127.0.0.1:53".parse::<std::net::SocketAddr>().unwrap()),
        )
        .await;
    let err = match result {
        Err(err) => err,
        Ok(..) => panic!("ss outbound hop unexpectedly supported UDP"),
    };
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("chain contains an ss hop"));
}

// Keep `Arc` referenced so this integration test also verifies `OutboundProxyClient`
// remains shareable in the service contexts that cache it.
#[test]
fn outbound_client_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arc<OutboundProxyClient>>();
}

fn run_mock_sip003_plugin(start_delay: Duration) {
    use std::{
        env,
        io::copy,
        net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
        thread,
    };

    thread::sleep(start_delay);

    let local_host = env::var("SS_LOCAL_HOST").unwrap();
    let local_port = env::var("SS_LOCAL_PORT").unwrap();
    let remote_host = env::var("SS_REMOTE_HOST").unwrap();
    let remote_port = env::var("SS_REMOTE_PORT").unwrap();
    assert_eq!(env::var("SS_PLUGIN_OPTIONS").as_deref(), Ok("mock-options"));

    let listener = StdTcpListener::bind(format!("{local_host}:{local_port}")).unwrap();
    for local in listener.incoming() {
        let local = local.unwrap();
        let remote = StdTcpStream::connect(format!("{remote_host}:{remote_port}")).unwrap();
        thread::spawn(move || {
            let mut local_reader = local.try_clone().unwrap();
            let mut remote_writer = remote.try_clone().unwrap();
            let forward = thread::spawn(move || copy(&mut local_reader, &mut remote_writer));

            let mut remote_reader = remote;
            let mut local_writer = local;
            let _ = copy(&mut remote_reader, &mut local_writer);
            let _ = forward.join();
        });
    }
}

/// Re-entered by `tcp_echo_through_first_shadowsocks_hop_plugin` as a SIP003
/// subprocess. Keeping it ignored prevents the normal test runner from blocking.
#[test]
#[ignore]
fn mock_sip003_plugin_process() {
    run_mock_sip003_plugin(Duration::ZERO);
}

/// Re-entered by `first_hop_plugin_start_failure_is_throttled_and_retried`
/// to emulate a plugin that starts shortly after the initial readiness timeout.
#[test]
#[ignore]
fn mock_sip003_plugin_starts_late() {
    run_mock_sip003_plugin(Duration::from_millis(3_250));
}
