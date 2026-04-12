//! HTTP CONNECT proxy client for tunneling through HTTP proxies

use std::io;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use shadowsocks::relay::socks5::Address;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// HTTP CONNECT proxy client for tunneling through HTTP proxies
pub struct HttpConnectClient;

impl HttpConnectClient {
    /// Perform HTTP CONNECT negotiation on an existing stream
    pub async fn conduct_connect<S>(
        stream: &mut S,
        target: &Address,
        proxy_auth: Option<(&str, &str)>,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let authority = match target {
            Address::SocketAddress(sa) => {
                if sa.is_ipv6() {
                    format!("[{}]:{}", sa.ip(), sa.port())
                } else {
                    sa.to_string()
                }
            }
            Address::DomainNameAddress(host, port) => format!("{host}:{port}"),
        };

        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n");

        if let Some((username, password)) = proxy_auth {
            let encoded = BASE64_STANDARD.encode(format!("{username}:{password}"));
            request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
        }

        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::with_capacity(1024);
        let mut buf = [0u8; 1024];

        let header_end = loop {
            if response.len() > 16 * 1024 {
                return Err(io::Error::other("HTTP CONNECT response header is too large"));
            }

            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading HTTP CONNECT response",
                ));
            }

            response.extend_from_slice(&buf[..n]);
            if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };

        let header = String::from_utf8_lossy(&response[..header_end]);
        let status_line = header.lines().next().unwrap_or_default();
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| io::Error::other(format!("invalid HTTP CONNECT response: {status_line}")))?;

        if status_code != 200 {
            return Err(io::Error::other(format!(
                "HTTP CONNECT proxy rejected tunnel with status {status_code}: {status_line}"
            )));
        }

        Ok(())
    }
}
