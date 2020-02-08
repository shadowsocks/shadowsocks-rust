//! Relay for TCP server that running on the server side

use std::{io, io::ErrorKind, net::SocketAddr};

use futures::{
    future::{self, Either},
    stream::{FuturesUnordered, StreamExt},
};
use log::{debug, error, info, trace};
use tokio::{
    self,
    net::{TcpListener, TcpStream},
};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{flow::SharedServerFlowStatistic, socks5::Address},
};

use super::{monitor::TcpMonStream, utils::connect_tcp_stream, CryptoStream, STcpStream};

#[allow(clippy::cognitive_complexity)]
async fn handle_client(
    context: SharedContext,
    flow_stat: SharedServerFlowStatistic,
    svr_cfg: &ServerConfig,
    socket: TcpStream,
    peer_addr: SocketAddr,
) -> io::Result<()> {
    let timeout = svr_cfg.timeout();

    if let Err(err) = socket.set_keepalive(timeout) {
        error!("Failed to set keep alive: {:?}", err);
    }

    trace!("Got connection addr: {} with proxy server: {:?}", peer_addr, svr_cfg);

    let mut stream = STcpStream::new(socket, timeout);
    stream.set_nodelay(context.config().no_delay)?;

    // Wrap with a data transfer monitor
    let stream = TcpMonStream::new(flow_stat, stream);

    // Do server-client handshake
    // Perform encryption IV exchange
    let mut stream = CryptoStream::new(context.clone(), stream, svr_cfg);

    // Read remote Address
    let remote_addr = match Address::read_from(&mut stream).await {
        Ok(o) => o,
        Err(err) => {
            error!(
                "Failed to decode Address, may be wrong method or key, peer {}, error: {}",
                peer_addr, err
            );
            return Err(From::from(err));
        }
    };

    debug!("Relay {} <-> {} establishing", peer_addr, remote_addr);

    let bind_addr = match context.config().local {
        None => None,
        Some(ref addr) => {
            let ba = addr.bind_addr(&*context).await?;
            Some(ba)
        }
    };

    let mut remote_stream = match remote_addr {
        Address::SocketAddress(ref saddr) => {
            if context.check_forbidden_ip(&saddr.ip()) {
                error!("{} is forbidden, failed to connect {}", saddr.ip(), saddr);
                let err = io::Error::new(
                    io::ErrorKind::Other,
                    format!("{} is forbidden, failed to connect {}", saddr.ip(), saddr),
                );
                return Err(err);
            }

            match connect_tcp_stream(saddr, &bind_addr).await {
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
            let result = lookup_then!(&*context, dname.as_str(), port, true, |addr| {
                match connect_tcp_stream(&addr, &bind_addr).await {
                    Ok(s) => Ok(s),
                    Err(err) => {
                        debug!(
                            "Failed to connect remote {}:{} (resolved: {}), {}, try others",
                            dname, port, addr, err
                        );
                        Err(err)
                    }
                }
            });

            match result {
                Ok((addr, s)) => {
                    trace!("Connected remote {}:{} (resolved: {})", dname, port, addr);
                    s
                }
                Err(err) => {
                    error!("Failed to connect remote {}:{}, {}", dname, port, err);
                    return Err(err);
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
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("Relay {} -> {} closed with error {}", peer_addr, remote_addr, err);
            } else {
                error!("Relay {} -> {} closed with error {}", peer_addr, remote_addr, err);
            }
        }
        Either::Right((Ok(_), _)) => trace!("Relay {} <- {} closed", peer_addr, remote_addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("Relay {} <- {} closed with error {}", peer_addr, remote_addr, err);
            } else {
                error!("Relay {} <- {} closed with error {}", peer_addr, remote_addr, err);
            }
        }
    }

    debug!("Relay {} <-> {} closing", peer_addr, remote_addr);

    Ok(())
}

/// Runs the server
pub async fn run(context: SharedContext, flow_stat: SharedServerFlowStatistic) -> io::Result<()> {
    let vec_fut = FuturesUnordered::new();

    for (idx, svr_cfg) in context.config().server.iter().enumerate() {
        let mut listener = {
            let addr = svr_cfg.plugin_addr().as_ref().unwrap_or_else(|| svr_cfg.addr());
            let addr = addr.bind_addr(&*context).await?;

            let listener = TcpListener::bind(&addr)
                .await
                .unwrap_or_else(|err| panic!("Failed to listen on {}, {}", addr, err));

            let local_addr = listener.local_addr().expect("Could not determine port bound to");
            info!("ShadowSocks TCP Listening on {}", local_addr);

            listener
        };

        // Clone and move into the server future
        let context = context.clone();
        let flow_stat = flow_stat.clone();

        vec_fut.push(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, peer_addr)) => {
                        let flow_stat = flow_stat.clone();
                        let context = context.clone();

                        tokio::spawn(async move {
                            // Retrieve server config reference from context again
                            //
                            // Because the svr_cfg outside doesn't live long enough. WHAT??
                            let svr_cfg = context.server_config(idx);

                            // Error is ignored because it is already logged
                            let _ = handle_client(context.clone(), flow_stat, svr_cfg, socket, peer_addr).await;
                        });
                    }
                    Err(err) => {
                        error!("Server run failed: {}", err);
                        break;
                    }
                }
            }
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
