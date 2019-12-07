//! TCP Relay Context

use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    config::{ServerAddr, ServerConfig},
    context::SharedContext,
};

use log::debug;
use tokio::{self, net::UdpSocket, time};

/// TCP Relay Server Context
pub struct TcpServerContext {
    tx: AtomicUsize,
    rx: AtomicUsize,
    context: SharedContext,
    svr_cfg: Arc<ServerConfig>,
}

const UPDATE_INTERVAL: Duration = Duration::from_secs(5);

pub type SharedTcpServerContext = Arc<TcpServerContext>;

impl TcpServerContext {
    /// Create a new server context
    pub fn new(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> SharedTcpServerContext {
        let ctx = TcpServerContext {
            tx: AtomicUsize::new(0),
            rx: AtomicUsize::new(0),
            context,
            svr_cfg,
        };

        let ctx = Arc::new(ctx);

        if ctx.context.config().manager_address.is_some() {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let mut interval = time::interval(UPDATE_INTERVAL);
                while ctx.context.server_running() {
                    interval.tick().await;

                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let _ = ctx.stat_interval().await;
                    });
                }
            });
        }

        ctx
    }

    pub fn context(&self) -> &SharedContext {
        &self.context
    }

    pub fn svr_cfg(&self) -> &Arc<ServerConfig> {
        &self.svr_cfg
    }

    pub fn incr_tx(&self, x: usize) {
        self.tx.fetch_add(x, Ordering::Release);
    }

    pub fn incr_rx(&self, x: usize) {
        self.rx.fetch_add(x, Ordering::Release);
    }

    async fn stat_interval(&self) -> io::Result<()> {
        let svr_cfg = self.svr_cfg.clone();
        let transmission = self.tx.load(Ordering::Acquire) + self.rx.load(Ordering::Acquire);

        let any_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut socket = UdpSocket::bind(&any_addr).await?;

        let payload = format!("stat: {{\"{}\": {}}}", svr_cfg.addr().port(), transmission);

        let maddr = self
            .context
            .config()
            .manager_address
            .as_ref()
            .expect("manager_address must not be None");

        debug!("Sending Tcp Relay to {}, payload: {}", maddr, payload);

        match maddr {
            ServerAddr::SocketAddr(ref addr) => {
                socket.send_to(payload.as_ref(), addr).await?;
            }
            #[cfg(feature = "trust-dns")]
            ServerAddr::DomainName(ref domain, ref port) => {
                use crate::relay::dns_resolver::resolve;

                let addrs = resolve(&*self.context, &domain[..], *port, false).await?;
                socket.send_to(payload.as_ref(), addrs[0]).await?;
            }
            #[cfg(not(feature = "trust-dns"))]
            ServerAddr::DomainName(ref domain, ref port) => {
                socket.send_to(payload.as_ref(), (domain.as_str(), *port)).await?;
            }
        }

        Ok(())
    }
}
