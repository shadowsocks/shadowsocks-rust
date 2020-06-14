//! Relay for TCP server that running on the server side

use std::{io, io::ErrorKind, net::SocketAddr};

use futures::{
    future::{self, Either},
    stream::{FuturesUnordered, StreamExt},
};
use log::{debug, error, info, trace, warn};
use tokio::{
    self,
    net::{TcpListener, TcpStream},
};

use crate::{
    config::ServerConfig,
    context::SharedContext,
    relay::{
        flow::{SharedMultiServerFlowStatistic, SharedServerFlowStatistic},
        socks5::Address,
        utils::try_timeout,
    },
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
        error!("failed to set keep alive: {:?}", err);
    }

    trace!("got connection addr {} with proxy server {:?}", peer_addr, svr_cfg);

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
                "failed to decode Address, may be wrong method or key, from client {}, error: {}",
                peer_addr, err
            );
            return Err(From::from(err));
        }
    };

    debug!("RELAY {} <-> {} establishing", peer_addr, remote_addr);

    // Check if remote_addr matches any ACL rules
    if context.check_outbound_blocked(&remote_addr).await {
        warn!("outbound {} is blocked by ACL rules", remote_addr);
        return Ok(());
    }

    let bind_addr = match context.config().local_addr {
        None => None,
        Some(ref addr) => {
            let ba = addr.bind_addr(&context).await?;
            Some(ba)
        }
    };

    let mut remote_stream = match remote_addr {
        Address::SocketAddress(ref saddr) => {
            // NOTE: ACL is already checked above, connect directly

            match try_timeout(connect_tcp_stream(saddr, &bind_addr), timeout).await {
                Ok(s) => {
                    debug!("connected to remote {}", saddr);
                    s
                }
                Err(err) => {
                    error!("failed to connect remote {}, {}", saddr, err);
                    return Err(err);
                }
            }
        }
        Address::DomainNameAddress(ref dname, port) => {
            let result = lookup_then!(&context, dname.as_str(), port, |addr| {
                match try_timeout(connect_tcp_stream(&addr, &bind_addr), timeout).await {
                    Ok(s) => Ok(s),
                    Err(err) => {
                        debug!(
                            "failed to connect remote {}:{} (resolved: {}), {}, try others",
                            dname, port, addr, err
                        );
                        Err(err)
                    }
                }
            });

            match result {
                Ok((addr, s)) => {
                    trace!("connected remote {}:{} (resolved: {})", dname, port, addr);
                    s
                }
                Err(err) => {
                    error!("failed to connect remote {}:{}, {}", dname, port, err);
                    return Err(err);
                }
            }
        }
    };

    debug!("RELAY {} <-> {} established", peer_addr, remote_addr);

    let (mut cr, mut cw) = stream.split();
    let (mut sr, mut sw) = remote_stream.split();

    use tokio::io::copy;

    // CLIENT -> SERVER
    let rhalf = copy(&mut cr, &mut sw);

    // CLIENT <- SERVER
    let whalf = copy(&mut sr, &mut cw);

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(_), _)) => trace!("RELAY {} -> {} closed", peer_addr, remote_addr),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("RELAY {} -> {} closed with error {}", peer_addr, remote_addr, err);
            } else {
                error!("RELAY {} -> {} closed with error {}", peer_addr, remote_addr, err);
            }
        }
        Either::Right((Ok(_), _)) => trace!("RELAY {} <- {} closed", peer_addr, remote_addr),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!("RELAY {} <- {} closed with error {}", peer_addr, remote_addr, err);
            } else {
                error!("RELAY {} <- {} closed with error {}", peer_addr, remote_addr, err);
            }
        }
    }

    debug!("RELAY {} <-> {} closing", peer_addr, remote_addr);

    Ok(())
}

/// Runs the server
pub async fn run(context: SharedContext, flow_stat: SharedMultiServerFlowStatistic) -> io::Result<()> {
    let vec_fut = FuturesUnordered::new();

    for (idx, svr_cfg) in context.config().server.iter().enumerate() {
        let mut listener = {
            let addr = svr_cfg.external_addr();
            let addr = addr.bind_addr(&context).await?;

            let listener = TcpListener::bind(&addr)
                .await
                .unwrap_or_else(|err| panic!("failed to listen on {}, {}", addr, err));

            let local_addr = listener.local_addr().expect("determine port bound to");
            info!("shadowsocks TCP listening on {}", local_addr);

            listener
        };

        // Clone and move into the server future
        let context = context.clone();
        let flow_stat = flow_stat
            .get(svr_cfg.addr().port())
            .expect("port not existed in multi-server flow statistic")
            .clone();

        vec_fut.push(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, peer_addr)) => {
                        // Check ACL rules
                        if context.check_client_blocked(&peer_addr).await {
                            warn!("client {} is blocked by ACL rules", peer_addr);
                            continue;
                        }

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
                        error!("server run failed: {}", err);
                        break;
                    }
                }
            }
        });
    }

    match vec_fut.into_future().await.0 {
        Some(()) => {
            error!("one of TCP servers exited unexpectly");
            let err = io::Error::new(io::ErrorKind::Other, "server exited unexpectly");
            Err(err)
        }
        None => unreachable!(),
    }
}
