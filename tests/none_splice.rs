//! TCP relays with the `none` cipher: byte-exactness, half-close, and which of the paths (the
//! kernel's `splice(2)` or the userspace copy) carried the bytes.

#![cfg(all(feature = "local-tunnel", feature = "server"))]

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use log::{LevelFilter, Log, Metadata, Record};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

use shadowsocks_service::{
    config::{Config, ConfigType},
    local::Server as LocalServer,
    run_server,
};

/// Counts the messages with which the splice relay says that it has ended
struct SpliceLogger;

static SPLICE_RELAYS: AtomicUsize = AtomicUsize::new(0);
/// Tests share the logger and the counter, so they run one at a time
static SERIAL: Mutex<()> = Mutex::new(());

impl Log for SpliceLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.target().ends_with("tcprelay::splice")
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) && record.args().to_string().starts_with("splice relay ends") {
            SPLICE_RELAYS.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn flush(&self) {}
}

fn init_logger() {
    static LOGGER: SpliceLogger = SpliceLogger;
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(LevelFilter::Trace);
    }
}

fn splice_relays() -> usize {
    SPLICE_RELAYS.load(Ordering::SeqCst)
}

/// `n` relays on splice(2) on Linux and Android, where it is used, and none elsewhere
fn on_splice_platforms(n: usize) -> usize {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        n
    } else {
        0
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Deterministic, non-repeating-looking bytes: the byte at `offset` of the stream `seed`
fn byte_at(seed: u64, offset: u64) -> u8 {
    let x = (offset ^ (seed << 32)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (x >> 56) as u8
}

fn fill(seed: u64, offset: u64, buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = byte_at(seed, offset + i as u64);
    }
}

async fn send_stream<W: AsyncWriteExt + Unpin>(w: &mut W, seed: u64, len: u64) {
    let mut buf = vec![0u8; 100_003]; // not a power of two on purpose
    let mut sent = 0;
    while sent < len {
        let n = buf.len().min((len - sent) as usize);
        fill(seed, sent, &mut buf[..n]);
        w.write_all(&buf[..n]).await.unwrap();
        sent += n as u64;
    }
}

/// Reads to EOF and checks every byte; returns the length
async fn check_stream<R: AsyncReadExt + Unpin>(r: &mut R, seed: u64) -> u64 {
    let mut buf = vec![0u8; 65_537];
    let mut expected = vec![0u8; buf.len()];
    let mut got = 0;
    loop {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            return got;
        }
        fill(seed, got, &mut expected[..n]);
        assert!(buf[..n] == expected[..n], "stream {seed} differs near offset {got}");
        got += n as u64;
    }
}

/// A TCP server on a free port that runs `handler` for every connection
async fn target_server<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(TcpStream) -> Fut + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::task::spawn_local(handler(stream));
        }
    });
    addr
}

struct Proxy {
    local_port: u16,
    server_port: u16,
    local_flow: std::sync::Arc<shadowsocks_service::net::FlowStat>,
}

/// An sslocal tunnel to `target` and an ssserver, both with `method`, and the `extra` settings
async fn proxy(method: &str, target: SocketAddr, local_extra: &str, server_extra: &str) -> Proxy {
    let local_port = free_port();
    let server_port = free_port();

    let local_config = Config::load_from_str(
        &format!(
            r#"{{
            "locals": [
                {{
                    "local_port": {local_port},
                    "local_address": "127.0.0.1",
                    "protocol": "tunnel",
                    "forward_address": "127.0.0.1",
                    "forward_port": {port}
                }}
            ],
            "server": "127.0.0.1",
            "server_port": {server_port},
            "password": "password",
            "method": "{method}"
            {local_extra}
        }}"#,
            port = target.port()
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
            "method": "{method}"
            {server_extra}
        }}"#
        ),
        ConfigType::Server,
    )
    .unwrap();

    let local = LocalServer::new(local_config).await.unwrap();
    let local_flow = local.context().flow_stat();
    tokio::task::spawn_local(async move {
        let _ = local.run().await;
    });
    tokio::task::spawn_local(async move {
        let _ = run_server(server_config).await;
    });

    // Wait for the listeners
    for port in [server_port, local_port] {
        let mut tries = 0;
        while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            tries += 1;
            assert!(tries < 200, "port {port} never came up");
            time::sleep(Duration::from_millis(50)).await;
        }
    }

    Proxy {
        local_port,
        server_port,
        local_flow,
    }
}

/// Runs a test body on a `LocalSet`, one test at a time, with a deadline
fn scenario<F: Future<Output = ()>>(body: F) {
    init_logger();
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    runtime
        .block_on(async { time::timeout(Duration::from_secs(120), local.run_until(body)).await })
        .expect("scenario timed out");
}

const BULK: u64 = 64 << 20;

/// 64 MiB up, EOF, then 64 MiB down: the answer is only sent once the client's half-close has made
/// it through both relays, so the reverse direction must survive the first EOF.
async fn bulk_half_close(method: &str, extra: &str, expect_splice: bool) {
    let target = target_server(|mut s| async move {
        let up = check_stream(&mut s, 1).await;
        assert_eq!(up, BULK);
        send_stream(&mut s, 2, BULK).await;
        s.shutdown().await.unwrap();
    })
    .await;
    let p = proxy(method, target, extra, extra).await;
    let before = splice_relays();

    let mut c = TcpStream::connect(("127.0.0.1", p.local_port)).await.unwrap();
    let (mut r, mut w) = c.split();
    let up = async {
        send_stream(&mut w, 1, BULK).await;
        w.shutdown().await.unwrap();
    };
    let down = async { check_stream(&mut r, 2).await };
    let ((), got) = tokio::join!(up, down);
    assert_eq!(got, BULK);
    drop(c);

    // the relays log when they end, which is after the client saw EOF
    time::sleep(Duration::from_millis(500)).await;
    let spliced = splice_relays() - before;
    if expect_splice {
        // one in sslocal, one in ssserver
        assert_eq!(spliced, on_splice_platforms(2), "both relays should have used splice");
    } else {
        assert_eq!(spliced, 0, "no relay should have used splice");
    }

    // the address header is counted on the way out, as for the other ciphers
    let header = 1 + 4 + 2;
    if method == "none" {
        assert_eq!(p.local_flow.tx(), BULK + header, "tx of sslocal");
        assert_eq!(p.local_flow.rx(), BULK, "rx of sslocal");
    }
}

#[test]
fn none_bulk_half_close_is_spliced() {
    scenario(bulk_half_close("none", "", true));
}

/// TCP Fast Open hides the outbound socket from the splice path (and from sslocal only: the server's
/// own outbound isn't TFO), so sslocal copies through userspace while ssserver still splices.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn none_bulk_half_close_with_fastopen_falls_back_in_sslocal() {
    scenario(async {
        let target = target_server(|mut s| async move {
            let up = check_stream(&mut s, 1).await;
            assert_eq!(up, BULK / 4);
            send_stream(&mut s, 2, BULK / 4).await;
            s.shutdown().await.unwrap();
        })
        .await;
        let p = proxy("none", target, r#", "fast_open": true"#, "").await;
        let before = splice_relays();

        let mut c = TcpStream::connect(("127.0.0.1", p.local_port)).await.unwrap();
        let (mut r, mut w) = c.split();
        let up = async {
            send_stream(&mut w, 1, BULK / 4).await;
            w.shutdown().await.unwrap();
        };
        let down = async { check_stream(&mut r, 2).await };
        let ((), got) = tokio::join!(up, down);
        assert_eq!(got, BULK / 4);
        drop(c);

        time::sleep(Duration::from_millis(500)).await;
        assert_eq!(splice_relays() - before, 1, "only ssserver should have used splice");
        assert_eq!(p.local_flow.tx(), BULK / 4 + 1 + 4 + 2);
        assert_eq!(p.local_flow.rx(), BULK / 4);
    });
}

/// The AEAD path must not be touched
#[test]
fn aead_bulk_half_close_is_not_spliced() {
    scenario(bulk_half_close("aes-256-gcm", "", false));
}

/// `true` if the kernel has Multipath TCP
#[cfg(any(target_os = "linux", target_os = "android"))]
fn mptcp_available() -> bool {
    // SAFETY: a socket that is closed right away
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_MPTCP) };
    if fd < 0 {
        return false;
    }
    unsafe { libc::close(fd) };
    true
}

/// Multipath TCP from sslocal to ssserver, and from ssserver to the target, which isn't MPTCP (that
/// connection falls back to TCP). The relays splice MPTCP sockets as they splice TCP ones.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn none_bulk_half_close_over_mptcp_is_spliced() {
    if !mptcp_available() {
        eprintln!("no MPTCP on this kernel, skipping");
        return;
    }
    scenario(bulk_half_close("none", r#", "mptcp": true"#, true));
}

/// Both directions at the same time, each ended by its own half-close
#[test]
fn none_full_duplex() {
    scenario(async {
        let target = target_server(|s| async move {
            let (mut r, mut w) = s.into_split();
            let send = async {
                send_stream(&mut w, 4, BULK / 2).await;
                w.shutdown().await.unwrap();
            };
            let (got, ()) = tokio::join!(check_stream(&mut r, 3), send);
            assert_eq!(got, BULK / 2);
        })
        .await;
        let p = proxy("none", target, "", "").await;

        let mut c = TcpStream::connect(("127.0.0.1", p.local_port)).await.unwrap();
        let (mut r, mut w) = c.split();
        let up = async {
            send_stream(&mut w, 3, BULK / 2).await;
            w.shutdown().await.unwrap();
        };
        let (got, ()) = tokio::join!(check_stream(&mut r, 4), up);
        assert_eq!(got, BULK / 2);
    });
}

/// Nothing from the client for longer than sslocal's 500 ms wait for a first packet: the handshake
/// goes out alone, and the relay starts afterwards.
#[test]
fn none_idle_client_then_data() {
    scenario(async {
        let target = target_server(|mut s| async move {
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.shutdown().await.unwrap();
        })
        .await;
        let p = proxy("none", target, "", "").await;
        let before = splice_relays();

        let mut c = TcpStream::connect(("127.0.0.1", p.local_port)).await.unwrap();
        time::sleep(Duration::from_millis(900)).await;
        c.write_all(b"late bytes").await.unwrap();
        c.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        c.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"late bytes");

        time::sleep(Duration::from_millis(300)).await;
        assert_eq!(splice_relays() - before, on_splice_platforms(2));
    });
}

/// The server speaks first (FTP, SMTP): its greeting must reach a client that said nothing
#[test]
fn none_server_speaks_first() {
    scenario(async {
        let target = target_server(|mut s| async move {
            s.write_all(b"220 hello\r\n").await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"QUIT\r\n");
            s.write_all(b"221 bye\r\n").await.unwrap();
        })
        .await;
        let p = proxy("none", target, "", "").await;

        let mut c = TcpStream::connect(("127.0.0.1", p.local_port)).await.unwrap();
        let mut greeting = [0u8; 11];
        c.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"220 hello\r\n");
        c.write_all(b"QUIT\r\n").await.unwrap();
        c.shutdown().await.unwrap();
        let mut rest = Vec::new();
        c.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"221 bye\r\n");
    });
}

/// A client that sends the header and the payload in one segment: ssserver reads the header byte by
/// byte, and the payload that follows has to survive the switch to the kernel relay.
#[test]
fn none_server_keeps_payload_sent_with_the_header() {
    scenario(async {
        let target = target_server(|mut s| async move {
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        })
        .await;
        let p = proxy("none", target, "", "").await;
        let before = splice_relays();

        // ATYP IPv4, address, port, then the payload
        let mut first = vec![0x01, 127, 0, 0, 1];
        first.extend_from_slice(&target.port().to_be_bytes());
        first.extend_from_slice(&[0xAB; 3000]);

        let mut c = TcpStream::connect(("127.0.0.1", p.server_port)).await.unwrap();
        c.write_all(&first).await.unwrap();
        c.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        c.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, vec![0xAB; 3000]);

        time::sleep(Duration::from_millis(300)).await;
        assert_eq!(splice_relays() - before, on_splice_platforms(1));
    });
}

/// Many short connections in a row and in parallel, each with its own pipes
#[test]
fn none_many_connections() {
    scenario(async {
        let target = target_server(|mut s| async move {
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        })
        .await;
        let p = proxy("none", target, "", "").await;
        let port = p.local_port;

        let mut tasks = Vec::new();
        for i in 0..64u64 {
            tasks.push(tokio::task::spawn_local(async move {
                let len = (i * 977) % 200_000;
                let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                let (mut r, mut w) = c.split();
                let up = async {
                    send_stream(&mut w, 100 + i, len).await;
                    w.shutdown().await.unwrap();
                };
                let (got, ()) = tokio::join!(check_stream(&mut r, 100 + i), up);
                assert_eq!(got, len);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    });
}

/// A connection that the ACL sends around the proxy is a plain TCP relay in sslocal, whatever the
/// cipher: byte-exact with half-close, and counted by neither flow statistic.
#[cfg(feature = "local")]
#[test]
fn bypassed_connection_is_spliced() {
    scenario(async {
        let target = target_server(|mut s| async move {
            let up = check_stream(&mut s, 7).await;
            assert_eq!(up, BULK / 4);
            send_stream(&mut s, 8, BULK / 4).await;
            s.shutdown().await.unwrap();
        })
        .await;

        let acl =
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("none-splice-acl-{}", std::process::id()));
        std::fs::write(&acl, "[bypass_all]\n[white_list]\n8.8.8.8\n").unwrap();
        let local_port = free_port();
        let mut config = Config::load_from_str(
            &format!(
                r#"{{
                "locals": [{{ "local_port": {local_port}, "local_address": "127.0.0.1", "protocol": "socks" }}],
                "server": "127.0.0.1",
                "server_port": 1,
                "password": "password",
                "method": "none"
            }}"#
            ),
            ConfigType::Local,
        )
        .unwrap();
        // not through the JSON: a Windows path would need escaping there
        config.acl = Some(shadowsocks_service::acl::AccessControl::load_from_file(&acl).unwrap());
        let local = LocalServer::new(config).await.unwrap();
        let flow = local.context().flow_stat();
        tokio::task::spawn_local(async move {
            let _ = local.run().await;
        });
        let mut tries = 0;
        let mut c = loop {
            match TcpStream::connect(("127.0.0.1", local_port)).await {
                Ok(c) => break c,
                Err(_) => {
                    tries += 1;
                    assert!(tries < 200);
                    time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        let before = splice_relays();

        // SOCKS5: no authentication, CONNECT to the target
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
        connect.extend_from_slice(&target.port().to_be_bytes());
        c.write_all(&connect).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed");

        let (mut r, mut w) = c.split();
        let up = async {
            send_stream(&mut w, 7, BULK / 4).await;
            w.shutdown().await.unwrap();
        };
        let (got, ()) = tokio::join!(check_stream(&mut r, 8), up);
        assert_eq!(got, BULK / 4);
        drop(c);

        time::sleep(Duration::from_millis(500)).await;
        assert_eq!(splice_relays() - before, on_splice_platforms(1));
        assert_eq!((flow.tx(), flow.rx()), (0, 0));
        let _ = std::fs::remove_file(acl);
    });
}
