#![cfg(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd"
))]

use byte_string::ByteStr;
use futures::future;
use log::debug;
use shadowsocks::{
    config::ServerType,
    context::Context,
    crypto::CipherKind,
    net::{AcceptOpts, ConnectOpts},
    relay::{
        socks5::Address,
        tcprelay::utils::{copy_from_encrypted, copy_to_encrypted},
    },
    ProxyClientStream, ProxyListener, ServerConfig,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

#[tokio::test]
async fn tcp_tunnel_tfo() {
    let _ = env_logger::try_init();

    let svr_cfg = ServerConfig::new(("127.0.0.1", 41000), "", CipherKind::NONE).unwrap();
    let svr_cfg_client = svr_cfg.clone();

    tokio::spawn(async move {
        let context = Context::new_shared(ServerType::Server);

        let mut accept_opts = AcceptOpts::default();
        accept_opts.tcp.fastopen = true;

        let listener = ProxyListener::bind_with_opts(context, &svr_cfg, accept_opts)
            .await
            .unwrap();

        while let Ok((mut stream, peer_addr)) = listener.accept().await {
            debug!("accepted {}", peer_addr);

            tokio::spawn(async move {
                let addr = stream.handshake().await.unwrap();
                let remote = match addr {
                    Address::SocketAddress(a) => TcpStream::connect(a).await.unwrap(),
                    Address::DomainNameAddress(name, port) => TcpStream::connect((name.as_str(), port)).await.unwrap(),
                };

                let (mut lr, mut lw) = tokio::io::split(stream);
                let (mut rr, mut rw) = remote.into_split();

                let l2r = copy_from_encrypted(CipherKind::NONE, &mut lr, &mut rw);
                let r2l = copy_to_encrypted(CipherKind::NONE, &mut rr, &mut lw);

                tokio::pin!(l2r);
                tokio::pin!(r2l);

                let _ = future::select(l2r, r2l).await;
            });
        }
    });

    tokio::task::yield_now().await;

    let context = Context::new_shared(ServerType::Local);

    let mut connect_opts = ConnectOpts::default();
    connect_opts.tcp.fastopen = true;

    let mut client = ProxyClientStream::connect_with_opts(
        context,
        &svr_cfg_client,
        ("www.example.com".to_owned(), 80),
        &connect_opts,
    )
    .await
    .unwrap();

    client
        .write_all(b"GET / HTTP/1.0\r\nHost: www.example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(client);

    let mut buffer = Vec::new();
    reader.read_until(b'\n', &mut buffer).await.unwrap();

    println!("{:?}", ByteStr::new(&buffer));

    const HTTP_RESPONSE_STATUS: &[u8] = b"HTTP/1.0 200 OK\r\n";
    assert!(buffer.starts_with(HTTP_RESPONSE_STATUS));
}
