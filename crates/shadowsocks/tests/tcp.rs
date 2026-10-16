use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use byte_string::ByteStr;
use futures::future;
use log::info;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Barrier,
};

use shadowsocks::{
    ProxyClientStream, ProxyListener,
    config::{ServerConfig, ServerType},
    context::Context,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        tcprelay::{
            proxy_stream::ProxyServerStream,
            utils::{copy_from_encrypted, copy_to_encrypted},
        },
    },
};

async fn handle_tcp_tunnel_server_client(
    method: CipherKind,
    mut stream: ProxyServerStream<TcpStream>,
) -> io::Result<()> {
    let addr = stream.handshake().await?;

    let mut remote = {
        let remote = match addr {
            Address::SocketAddress(ref sa) => TcpStream::connect(sa).await?,
            Address::DomainNameAddress(ref dname, port) => TcpStream::connect((dname.as_str(), port)).await?,
        };

        info!("connected to remote {}", addr);
        remote
    };

    let (mut sr, mut sw) = tokio::io::split(stream);
    let (mut mr, mut mw) = remote.split();

    let l2r = copy_from_encrypted(method, &mut sr, &mut mw);
    let r2l = copy_to_encrypted(method, &mut mr, &mut sw);

    tokio::pin!(l2r);
    tokio::pin!(r2l);

    let _ = future::select(l2r, r2l).await;

    info!("TCP tunnel server finished");

    Ok(())
}

async fn handle_tcp_tunnel_local_client(
    context: Arc<Context>,
    svr_cfg: Arc<ServerConfig>,
    mut stream: TcpStream,
) -> io::Result<()> {
    let target_addr = Address::from(("www.example.com".to_owned(), 80));

    let remote = ProxyClientStream::connect(context, &svr_cfg, target_addr).await?;

    let (mut lr, mut lw) = stream.split();
    let (mut sr, mut sw) = tokio::io::split(remote);

    let l2s = copy_to_encrypted(svr_cfg.method(), &mut lr, &mut sw);
    let s2l = copy_from_encrypted(svr_cfg.method(), &mut sr, &mut lw);

    tokio::pin!(l2s);
    tokio::pin!(s2l);

    let _ = future::select(l2s, s2l).await;

    info!("TCP tunnel client finished");

    Ok(())
}

async fn tcp_tunnel_example(
    server_addr: SocketAddr,
    local_addr: SocketAddr,
    password: &str,
    method: CipherKind,
) -> io::Result<()> {
    let svr_cfg_server = ServerConfig::new(server_addr, password, method).unwrap();
    let svr_cfg_local = svr_cfg_server.clone();

    let ctx_server = Context::new_shared(ServerType::Server);
    let ctx_local = Context::new_shared(ServerType::Local);

    let barrier_server = Arc::new(Barrier::new(3));
    let barrier_local = barrier_server.clone();
    let barrier = barrier_local.clone();

    tokio::spawn(async move {
        let svr_cfg_server = Arc::new(svr_cfg_server);

        let listener = ProxyListener::bind(ctx_server, &svr_cfg_server).await.unwrap();
        info!("server listening on {}", listener.local_addr().unwrap());

        barrier_server.wait().await;

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("server accepted stream {}", peer_addr);
            tokio::spawn(handle_tcp_tunnel_server_client(svr_cfg_server.method(), stream));
        }
    });

    tokio::spawn(async move {
        let svr_cfg_local = Arc::new(svr_cfg_local);

        let listener = TcpListener::bind(local_addr).await.unwrap();
        info!("local listening on {}", listener.local_addr().unwrap());

        barrier_local.wait().await;

        while let Ok((stream, peer_addr)) = listener.accept().await {
            info!("local accepted stream {}", peer_addr);

            let context = ctx_local.clone();
            let svr_cfg = svr_cfg_local.clone();
            tokio::spawn(handle_tcp_tunnel_local_client(context, svr_cfg, stream));
        }
    });

    barrier.wait().await;

    let mut client = TcpStream::connect(local_addr).await?;

    const HTTP_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    client.write_all(HTTP_REQUEST).await?;

    let mut reader = BufReader::new(client);

    let mut buffer = Vec::new();
    reader.read_until(b'\n', &mut buffer).await?;

    println!("{:?}", ByteStr::new(&buffer));

    const HTTP_RESPONSE_STATUS: &[u8] = b"HTTP/1.1 200 OK\r\n";
    assert!(buffer.starts_with(HTTP_RESPONSE_STATUS));

    Ok(())
}

#[cfg(feature = "aead-cipher")]
#[tokio::test]
async fn tcp_tunnel_aead() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:31001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:31101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(server_addr, local_addr, "p$p", CipherKind::AES_128_GCM)
        .await
        .unwrap();
}

#[cfg(feature = "stream-cipher")]
#[tokio::test]
async fn tcp_tunnel_stream() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:32001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:32101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(server_addr, local_addr, "p$p", CipherKind::AES_128_CFB128)
        .await
        .unwrap();
}

#[tokio::test]
async fn tcp_tunnel_none() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:33001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:33101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(server_addr, local_addr, "", CipherKind::NONE)
        .await
        .unwrap();
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn tcp_tunnel_aead_2022_aes() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:34001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:34101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(
        server_addr,
        local_addr,
        "3L69X4PF2eSL/JSLkoWnXg==",
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    )
    .await
    .unwrap();
}

// https://github.com/shadowsocks/shadowsocks-rust/issues/2184
//
// Clients that trigger the handshake with an empty write (server-first protocols) must not
// generate a header with no payload and padding 0, which servers MUST reject according to
// the AEAD-2022 spec (SIP022).
#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn tcp_aead_2022_handshake_with_empty_payload() {
    let _ = env_logger::try_init();

    const PASSWORD: &str = "3L69X4PF2eSL/JSLkoWnXg==";
    let method = CipherKind::AEAD2022_BLAKE3_AES_128_GCM;

    let target_addr = Address::from(("www.example.com".to_owned(), 80));

    let svr_cfg = Arc::new(
        ServerConfig::new("127.0.0.1:34001".parse::<SocketAddr>().unwrap(), PASSWORD, method).unwrap(),
    );

    let ctx_server = Context::new_shared(ServerType::Server);
    let ctx_local = Context::new_shared(ServerType::Local);

    for _ in 0..1000 {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);

        let mut server = ProxyServerStream::from_stream(ctx_server.clone(), server_side, method, svr_cfg.key());
        let mut client =
            ProxyClientStream::from_stream(ctx_local.clone(), client_side, &svr_cfg, target_addr.clone());

        // NOTE: write_all(&[]) would be a no-op, so call write() directly
        // to trigger the handshake with an empty first payload.
        let n = client.write(&[]).await.unwrap();
        assert_eq!(n, 0);

        let addr = server.handshake().await.unwrap();
        assert_eq!(addr, target_addr);
    }
}

#[cfg(feature = "aead-cipher-2022")]
#[tokio::test]
async fn tcp_tunnel_aead_2022_chacha20() {
    let _ = env_logger::try_init();

    let server_addr = "127.0.0.1:35001".parse::<SocketAddr>().unwrap();
    let local_addr = "127.0.0.1:35101".parse::<SocketAddr>().unwrap();
    tcp_tunnel_example(
        server_addr,
        local_addr,
        "VUw3mGWIpil2z2DKiyauE2Sp9KyE2ab8dulciawe74o",
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
    )
    .await
    .unwrap();
}

/// The methods of the first-packet tests, with a password each
fn first_packet_methods() -> Vec<(CipherKind, &'static str)> {
    #[allow(unused_mut)]
    let mut methods = vec![(CipherKind::NONE, "")];
    #[cfg(feature = "stream-cipher")]
    methods.push((CipherKind::AES_128_CFB128, "p$p"));
    #[cfg(feature = "aead-cipher")]
    methods.push((CipherKind::AES_128_GCM, "p$p"));
    #[cfg(feature = "aead-cipher-2022")]
    methods.push((CipherKind::AEAD2022_BLAKE3_AES_128_GCM, "3L69X4PF2eSL/JSLkoWnXg=="));
    methods
}

// ProxyClientStream sends the target address together with the payload of the first write. That
// write must not report bytes that it didn't send: the `none` cipher writes to the stream as it is,
// which may take fewer bytes than given, and the AEAD ciphers encrypt at most one chunk per write.
#[tokio::test]
async fn tcp_first_write_larger_than_one_stream_write() {
    let _ = env_logger::try_init();

    let target_addr = Address::from(("www.example.com".to_owned(), 80));
    let payload = (0..100_000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>();

    let ctx_server = Context::new_shared(ServerType::Server);
    let ctx_local = Context::new_shared(ServerType::Local);

    for (method, password) in first_packet_methods() {
        let svr_cfg = ServerConfig::new("127.0.0.1:0".parse::<SocketAddr>().unwrap(), password, method).unwrap();

        // A pipe that holds less than the first packet
        let (client_side, server_side) = tokio::io::duplex(4096);

        let mut server = ProxyServerStream::from_stream(ctx_server.clone(), server_side, method, svr_cfg.key());
        let mut client = ProxyClientStream::from_stream(ctx_local.clone(), client_side, &svr_cfg, target_addr.clone());

        let write = async {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        };
        let read = async {
            let addr = server.handshake().await.unwrap();
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            (addr, received)
        };
        let ((), (addr, received)) = tokio::join!(write, read);

        assert_eq!(addr, target_addr, "{method}");
        assert_eq!(received.len(), payload.len(), "{method}");
        assert!(received == payload, "{method}: the payload differs");
    }
}

/// A stream that takes nothing while it is closed, then everything. It registers no waker: the
/// test polls by hand.
#[derive(Default)]
struct Gate {
    open: bool,
    written: Vec<u8>,
}

impl AsyncRead for Gate {
    fn poll_read(self: Pin<&mut Self>, _: &mut task::Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Gate {
    fn poll_write(self: Pin<&mut Self>, _: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.open {
            return Poll::Pending;
        }
        this.written.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// After Poll::Pending, the caller may come back with a longer buffer (tokio's copy appends what it
// has read in the meantime, see #2175). Only the payload that went into the first packet has been
// written then, and if there was none (a handshake without data), the new bytes are written next.
#[tokio::test]
async fn tcp_first_write_retried_with_more_data() {
    let _ = env_logger::try_init();

    let target_addr = Address::from(("www.example.com".to_owned(), 80));

    let ctx_server = Context::new_shared(ServerType::Server);
    let ctx_local = Context::new_shared(ServerType::Local);

    for (method, password) in first_packet_methods() {
        let svr_cfg = ServerConfig::new("127.0.0.1:0".parse::<SocketAddr>().unwrap(), password, method).unwrap();

        // The first buffer, the longer one that the caller comes back with, and what that call reports
        for (first, retry, reported) in [(&b"a"[..], &b"ab"[..], 1), (&b""[..], &b"ab"[..], 2)] {
            let mut client =
                ProxyClientStream::from_stream(ctx_local.clone(), Gate::default(), &svr_cfg, target_addr.clone());
            let mut cx = task::Context::from_waker(futures::task::noop_waker_ref());

            assert!(Pin::new(&mut client).poll_write(&mut cx, first).is_pending());
            client.get_mut().open = true;
            let n = match Pin::new(&mut client).poll_write(&mut cx, retry) {
                Poll::Ready(Ok(n)) => n,
                other => panic!("{method}: {other:?}"),
            };
            assert_eq!(n, reported, "{method}: first write {first:?}");
            client.write_all(&retry[n..]).await.unwrap();

            let wire = std::mem::take(&mut client.get_mut().written);
            let mut server = ProxyServerStream::from_stream(
                ctx_server.clone(),
                tokio::io::join(&wire[..], tokio::io::sink()),
                method,
                svr_cfg.key(),
            );
            assert_eq!(server.handshake().await.unwrap(), target_addr, "{method}");
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, retry, "{method}: first write {first:?}");
        }
    }
}
