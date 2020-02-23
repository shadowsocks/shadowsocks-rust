//! Relay for TCP server that running on local environment

use std::{io, time::Duration};

use bytes::BytesMut;
use log::{debug, error, trace};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::{
    config::{ConfigType, ServerAddr, ServerConfig},
    context::{Context, SharedContext},
    relay::{socks5::Address, utils::try_timeout},
};

use super::{http_local, redir_local, socks5_local, tunnel_local, CryptoStream, STcpStream};

/// Starts a TCP local server
pub async fn run(context: SharedContext) -> io::Result<()> {
    match context.config().config_type {
        ConfigType::TunnelLocal => tunnel_local::run(context).await,
        ConfigType::Socks5Local => socks5_local::run(context).await,
        ConfigType::HttpLocal => http_local::run(context).await,
        ConfigType::RedirLocal => redir_local::run(context).await,
        ConfigType::Server => unreachable!(),
        ConfigType::Manager => unreachable!(),
    }
}

async fn connect_proxy_server_internal(
    context: &Context,
    orig_svr_addr: &ServerAddr,
    svr_addr: &ServerAddr,
    timeout: Option<Duration>,
) -> io::Result<STcpStream> {
    match svr_addr {
        ServerAddr::SocketAddr(ref addr) => {
            let stream = try_timeout(TcpStream::connect(addr), timeout).await?;
            debug!("connected proxy {} ({})", orig_svr_addr, addr);
            Ok(STcpStream::new(stream, timeout))
        }
        ServerAddr::DomainName(ref domain, port) => {
            let result = lookup_then!(context, domain.as_str(), *port, |addr| {
                match try_timeout(TcpStream::connect(addr), timeout).await {
                    Ok(s) => Ok(STcpStream::new(s, timeout)),
                    Err(e) => {
                        debug!(
                            "failed to connect proxy {} ({}:{} ({})) try another (err: {})",
                            orig_svr_addr, domain, port, addr, e
                        );
                        Err(e)
                    }
                }
            });

            match result {
                Ok((addr, s)) => {
                    debug!("connected proxy {} ({}:{} ({}))", orig_svr_addr, domain, port, addr);
                    Ok(s)
                }
                Err(err) => {
                    error!(
                        "failed to connect proxy {} ({}:{}), {}",
                        orig_svr_addr, domain, port, err
                    );
                    Err(err)
                }
            }
        }
    }
}

/// Connect to proxy server with `ServerConfig`
pub(crate) async fn connect_proxy_server(context: &Context, svr_cfg: &ServerConfig) -> io::Result<STcpStream> {
    let timeout = svr_cfg.timeout();

    let svr_addr = match context.config().config_type {
        ConfigType::Server => svr_cfg.addr(),
        ConfigType::Socks5Local | ConfigType::TunnelLocal | ConfigType::HttpLocal | ConfigType::RedirLocal => {
            svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr())
        }
        ConfigType::Manager => unreachable!("ConfigType::Manager shouldn't need to connect to proxy server"),
    };

    // Retry if connect failed
    //
    // FIXME: This won't work if server is actually down.
    //        Probably we should retry with another server.
    //
    // Also works if plugin is starting
    const RETRY_TIMES: i32 = 3;

    let orig_svr_addr = svr_cfg.addr();
    trace!(
        "connecting to proxy {} ({}), timeout: {:?}",
        orig_svr_addr,
        svr_addr,
        timeout
    );

    let mut last_err = None;
    for retry_time in 0..RETRY_TIMES {
        match connect_proxy_server_internal(context, orig_svr_addr, svr_addr, timeout).await {
            Ok(mut s) => {
                // IMPOSSIBLE, won't fail, but just a guard
                if let Err(err) = s.set_nodelay(context.config().no_delay) {
                    error!("failed to set TCP_NODELAY on remote socket, error: {:?}", err);
                }

                return Ok(s);
            }
            Err(err) => {
                // Connection failure, retry
                debug!(
                    "failed to connect {}, retried {} times (last err: {})",
                    svr_addr, retry_time, err
                );
                last_err = Some(err);

                // Yield and let the others' run
                //
                // It may take some time for scheduler to resume this coroutine.
                tokio::task::yield_now().await;
            }
        }
    }

    let last_err = last_err.unwrap();
    error!(
        "failed to connect {}, retried {} times, last_err: {}",
        svr_addr, RETRY_TIMES, last_err
    );
    Err(last_err)
}

/// Handshake logic for ShadowSocks Client
pub(crate) async fn proxy_server_handshake(
    context: SharedContext,
    remote_stream: STcpStream,
    svr_cfg: &ServerConfig,
    relay_addr: &Address,
) -> io::Result<CryptoStream<STcpStream>> {
    let mut stream = CryptoStream::new(context, remote_stream, svr_cfg);

    trace!("got encrypt stream and going to send addr: {:?}", relay_addr);

    // Send relay address to remote
    //
    // NOTE: `Address` handshake packets are very small in most cases,
    // so it will be sent with the IV/Nonce data (implemented inside `CryptoStream`).
    //
    // For lower latency, first packet should be sent back quickly,
    // so TCP_NODELAY should be kept enabled until the first data packet is received.
    let mut addr_buf = BytesMut::with_capacity(relay_addr.serialized_len());
    relay_addr.write_to_buf(&mut addr_buf);
    stream.write_all(&addr_buf).await?;

    // Here we should keep the TCP_NODELAY set until the first packet is received.
    // https://github.com/shadowsocks/shadowsocks-libev/pull/746
    //
    // Reset TCP_NODELAY after the first packet is received and sent back.

    Ok(stream)
}
