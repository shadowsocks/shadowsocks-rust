//! Relay for TCP server that running on the server side

use std::{io, net::SocketAddr, sync::Arc};

use crate::relay::{dns_resolver::resolve, socks5::Address};

use crate::context::SharedContext;

use futures::{
    future::{self, Either},
    stream::{FuturesUnordered, StreamExt},
};
use log::{debug, error, info, trace};
use tokio::{
    self,
    net::{TcpListener, TcpStream},
};

use super::{
    context::{SharedTcpServerContext, TcpServerContext},
    monitor::TcpMonStream,
    CryptoStream, STcpStream,
};

#[allow(clippy::cognitive_complexity)]
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

    let stream = TcpMonStream::new(
        svr_context.clone(),
        STcpStream::new(socket, svr_context.svr_cfg().timeout()),
    );

    // Do server-client handshake
    // Perform encryption IV exchange
    let mut stream = CryptoStream::new(stream, svr_context.svr_cfg().clone());

    // Read remote Address
    let remote_addr = match Address::read_from(&mut stream).await {
        Ok(o) => o,
        Err(err) => {
            error!(
                "Failed to decode Address, may be wrong method or key, peer {}",
                peer_addr
            );
            return Err(From::from(err));
        }
    };

    debug!("Relay {} <-> {} establishing", peer_addr, remote_addr);

    let context = svr_context.context();

    let mut remote_stream = match remote_addr {
        Address::SocketAddress(ref saddr) => {
            if context.config().forbidden_ip.contains(&saddr.ip()) {
                error!("{} is forbidden, failed to connect {}", saddr.ip(), saddr);
                let err = io::Error::new(
                    io::ErrorKind::Other,
                    format!("{} is forbidden, failed to connect {}", saddr.ip(), saddr),
                );
                return Err(err);
            }

            match TcpStream::connect(saddr).await {
                Ok(s) => {
                    debug!("Connected to remote {}", saddr);
                    s
                }
                Err(err) => {
                    error!("Failed to connect remote {}, {}", saddr, err);
                    return Err(err);
                }
            }
        }
        Address::DomainNameAddress(ref dname, port) => {
            let addrs = match resolve(context.clone(), dname.as_str(), port, true).await {
                Ok(r) => r,
                Err(err) => {
                    error!("Failed to resolve {}, {}", dname, err);
                    return Err(err);
                }
            };

            let mut last_err: Option<io::Error> = None;
            let mut stream_opt = None;
            for addr in &addrs {
                match TcpStream::connect(addr).await {
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
                Some(s) => {
                    debug!("Connected to remote {}:{}", dname, port);
                    s
                }
                None => {
                    let err = last_err.unwrap();
                    error!("Failed to connect remote {}:{}, {}", dname, port, err);
                    return Err(io::Error::new(io::ErrorKind::Other, err));
                }
            }
        }
    };

    debug!("Relay {} <-> {} established", peer_addr, remote_addr);

    let (mut cr, mut cw) = stream.split();
    let (mut sr, mut sw) = remote_stream.split();

    use tokio::io::copy;

    // CLIENT -> SERVER
    let rhalf = copy(&mut cr, &mut sw);

    // CLIENT <- SERVER
    let whalf = copy(&mut sr, &mut cw);

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(_), _)) => trace!("Relay {} -> {} closed", peer_addr, remote_addr),
        Either::Left((Err(err), _)) => trace!("Relay {} -> {} closed with error {:?}", peer_addr, remote_addr, err),
        Either::Right((Ok(_), _)) => trace!("Relay {} <- {} closed", peer_addr, remote_addr),
        Either::Right((Err(err), _)) => trace!("Relay {} <- {} closed with error {:?}", peer_addr, remote_addr, err),
    }

    debug!("Relay {} <-> {} closing", peer_addr, remote_addr);

    Ok(())
}

/// Runs the server
pub async fn run(context: SharedContext) -> io::Result<()> {
    let vec_fut = FuturesUnordered::new();

    for svr_cfg in &context.config().server {
        let mut listener = {
            let addr = svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr());
            let addr = addr.listen_addr();

            let listener = TcpListener::bind(&addr)
                .await
                .unwrap_or_else(|err| panic!("Failed to listen, {}", err));

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
