//! Shadowsocks TCP server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures::future::{self, Either};
use log::{debug, error, info, trace, warn};
use shadowsocks::{
    crypto::v1::CipherKind,
    net::TcpStream as OutboundTcpStream,
    relay::{
        socks5::Address,
        tcprelay::{
            utils::{copy_from_encrypted, copy_to_encrypted},
            ProxyServerStream,
        },
    },
    ProxyListener,
    ServerConfig,
};
use tokio::{net::TcpStream as TokioTcpStream, time};

use crate::net::{utils::ignore_until_end, MonProxyStream};

use super::context::ServiceContext;

pub struct TcpServer {
    context: Arc<ServiceContext>,
    nodelay: bool,
}

impl TcpServer {
    pub fn new(context: Arc<ServiceContext>, nodelay: bool) -> TcpServer {
        TcpServer { context, nodelay }
    }

    pub async fn run(self, svr_cfg: &ServerConfig) -> io::Result<()> {
        let listener = ProxyListener::bind(self.context.context(), svr_cfg).await?;

        info!(
            "shadowsocks tcp server listening on {}, inbound address {}",
            listener.local_addr().expect("listener.local_addr"),
            svr_cfg.addr()
        );

        loop {
            let (local_stream, peer_addr) = match listener
                .accept_map(|s| MonProxyStream::from_stream(s, self.context.flow_stat()))
                .await
            {
                Ok(s) => s,
                Err(err) => {
                    error!("tcp server accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if self.nodelay {
                let stream = local_stream.get_ref().get_ref();
                stream.set_nodelay(true)?;
            }

            let client = TcpServerClient {
                context: self.context.clone(),
                nodelay: self.nodelay,
                method: svr_cfg.method(),
                peer_addr,
                stream: local_stream,
            };

            tokio::spawn(async move {
                if let Err(err) = client.serve().await {
                    debug!("tcp server stream aborted with error: {}", err);
                }
            });
        }
    }
}

struct TcpServerClient {
    context: Arc<ServiceContext>,
    nodelay: bool,
    method: CipherKind,
    peer_addr: SocketAddr,
    stream: ProxyServerStream<MonProxyStream<TokioTcpStream>>,
}

impl TcpServerClient {
    async fn serve(mut self) -> io::Result<()> {
        let target_addr = match Address::read_from(&mut self.stream).await {
            Ok(a) => a,
            Err(err) => {
                // https://github.com/shadowsocks/shadowsocks-rust/issues/292
                //
                // Keep connection open.
                warn!(
                    "handshake failed, maybe wrong method or key, or under reply attacks. peer: {}, error: {}",
                    self.peer_addr, err
                );
                let _ = ignore_until_end(&mut self.stream).await;
                return Ok(());
            }
        };

        trace!(
            "accepted tcp client connection {}, establishing tunnel to {}",
            self.peer_addr,
            target_addr
        );

        if self.context.check_outbound_blocked(&target_addr).await {
            error!(
                "tcp client {} outbound {} blocked by ACL rules",
                self.peer_addr, target_addr
            );
            return Ok(());
        }

        let mut remote_stream = OutboundTcpStream::connect_remote_with_opts(
            self.context.context_ref(),
            &target_addr,
            self.context.connect_opts_ref(),
        )
        .await?;

        if self.nodelay {
            remote_stream.set_nodelay(true)?;
        }

        let (mut lr, mut lw) = self.stream.into_split();
        let (mut rr, mut rw) = remote_stream.split();

        let l2r = copy_to_encrypted(self.method, &mut lr, &mut rw);
        let r2l = copy_from_encrypted(self.method, &mut rr, &mut lw);

        tokio::pin!(l2r);
        tokio::pin!(r2l);

        debug!(
            "established tcp tunnel {} <-> {} with {:?}",
            self.peer_addr,
            target_addr,
            self.context.connect_opts_ref()
        );

        match future::select(l2r, r2l).await {
            Either::Left((Ok(..), ..)) => {
                trace!("tcp tunnel {} -> {} closed", self.peer_addr, target_addr);
            }
            Either::Left((Err(err), ..)) => {
                trace!(
                    "tcp tunnel {} -> {} closed with error: {}",
                    self.peer_addr,
                    target_addr,
                    err
                );
            }
            Either::Right((Ok(..), ..)) => {
                trace!("tcp tunnel {} <- {} closed", self.peer_addr, target_addr);
            }
            Either::Right((Err(err), ..)) => {
                trace!(
                    "tcp tunnel {} <- {} closed with error: {}",
                    self.peer_addr,
                    target_addr,
                    err
                );
            }
        }

        Ok(())
    }
}
