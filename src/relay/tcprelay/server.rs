//! Relay for TCP server that running on the server side

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use crate::relay::{
    dns_resolver::resolve,
    socks5::Address,
    tcprelay::crypto_io::{DecryptedRead, EncryptedWrite},
};

use crate::context::SharedContext;

use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error, info, trace};
use tokio::{
    self,
    future::FutureExt,
    io::{AsyncRead, AsyncWrite},
    net::{
        tcp::split::{TcpStreamReadHalf, TcpStreamWriteHalf},
        TcpListener,
        TcpStream,
    },
};

use super::{
    context::{SharedTcpServerContext, TcpServerContext},
    monitor::TcpMonStream,
    proxy_handshake,
    tunnel,
    DecryptedHalf,
    EncryptedHalf,
};

use crate::relay::utils::try_timeout;

async fn handle_client(
    svr_context: SharedTcpServerContext,
    socket: TcpStream,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    if let Err(err) = socket.set_keepalive(svr_context.svr_cfg().timeout()) {
        error!("Failed to set keep alive: {:?}", err);
    }

    if svr_context.context().config().no_delay {
        if let Err(err) = socket.set_nodelay(true) {
            error!("Failed to set no delay: {:?}", err);
        }
    }

    trace!(
        "Got connection addr: {} with proxy server: {:?}",
        peer_addr,
        svr_context.svr_cfg()
    );

    let (r, w) = socket.split();

    // Wraps for monitor
    let r = TcpMonStream::new(svr_context, r);
    let w = TcpMonStream::new(svr_context, w);

    // 1. Handshake
    // Do server-client handshake
    // Perform encryption IV exchange
    let (r, w) = match proxy_handshake(r, w, svr_context.svr_cfg().clone()).await {
        Ok(o) => o,
        Err(err) => {
            error!("Failed to handshake with peer {}, {}", peer_addr, err);
            return Err(err);
        }
    };

    let timeout = svr_context.svr_cfg().timeout();

    // Read remote Address
    let remote_addr = match try_timeout(Address::read_from(&mut r), timeout).await {
        Ok(o) => o,
        Err(err) => {
            error!(
                "Failed to decode Address, may be wrong method or key, peer {}",
                peer_addr
            );
            return Err(err);
        }
    };

    debug!("Received relay request {} <-> {}", peer_addr, remote_addr);

    let context = svr_context.context();

    let remote_stream = match remote_addr {
        Address::SocketAddress(ref saddr) => {
            if context.config().forbidden_ip.contains(&saddr.ip()) {
                error!("{} is forbidden, failed to connect {}", saddr.ip(), saddr);
                let err = io::Error::new(
                    io::ErrorKind::Other,
                    format!("{} is forbidden, failed to connect {}", saddr.ip(), saddr),
                );
                return Err(err);
            }

            match try_timeout(TcpStream::connect(saddr), timeout).await {
                Ok(s) => s,
                Err(err) => {
                    error!("Failed to connect remote {}, {}", saddr, err);
                    return Err(err);
                }
            }
        }
        Address::DomainNameAddress(dname, port) => {
            let addrs = match try_timeout(resolve(context.clone(), dname.as_str(), port, true), timeout).await {
                Ok(r) => r,
                Err(err) => {
                    error!("Failed to resolve {}, {}", dname, err);
                    return Err(err);
                }
            };

            let mut last_err: Option<io::Error> = None;
            let mut stream_opt = None;
            for addr in &addrs {
                match try_timeout(TcpStream::connect(addr), timeout).await {
                    Ok(s) => stream_opt = Some(s),
                    Err(err) => {
                        error!(
                            "Failed to connect remote {}:{} (resolved: {}), {}, try others",
                            dname, port, addr, err
                        );
                        last_err = Some(err);
                    }
                }
            }

            match stream_opt {
                Some(s) => s,
                None => {
                    let err = last_err.unwrap();
                    error!("Failed to connect remote {}:{}, {}", dname, port, err);
                    return Err(io::Error::new(io::ErrorKind::Other, err));
                }
            }
        }
    };

    Ok(())
}

/// Runs the server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let mut vec_fut = FuturesUnordered::new();

    for svr_cfg in &context.config().server {
        let listener = {
            let addr = svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr());
            let addr = addr.listen_addr();

            let listener = TcpListener::bind(&addr).unwrap_or_else(|err| panic!("Failed to listen, {}", err));

            info!("ShadowSocks TCP Listening on {}", addr);
            listener
        };

        let svr_cfg = Arc::new(svr_cfg.clone());
        let context = context.clone();
        let svr_context = TcpServerContext::new(context.clone(), svr_cfg.clone());

        struct CloseGuard(SharedTcpServerContext);
        impl Drop for CloseGuard {
            fn drop(&mut self) {
                self.0.close();
            }
        }

        let close_guard = CloseGuard(svr_context.clone());

        vec_fut.push(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, peer_addr)) => {
                        let svr_context = svr_context.clone();
                        tokio::spawn(async move {
                            let _ = handle_client(svr_context, socket, peer_addr).await;
                        });
                    }
                    Err(err) => {
                        error!("Server run failed: {}", err);
                        break;
                    }
                }
            }

            drop(close_guard);
        });
    }

    match vec_fut.into_future().await.0 {
        Some(()) => {
            error!("One of TCP servers exited unexpectly");
            let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
            Err(err)
        }
        None => unreachable!(),
    }
}
