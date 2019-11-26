//! TCP Relay Context

use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    config::{ServerAddr, ServerConfig},
    context::SharedContext,
    relay::dns_resolver::resolve,
};

use log::debug;
use tokio::{self, net::UdpSocket, time};

/// TCP Relay Server Context
pub struct TcpServerContext {
    tx: AtomicUsize,
    rx: AtomicUsize,
    context: SharedContext,
    stop_flag: Arc<AtomicBool>,
    svr_cfg: Arc<ServerConfig>,
}

const UPDATE_INTERVAL: Duration = Duration::from_secs(5);

pub type SharedTcpServerContext = Arc<TcpServerContext>;

impl TcpServerContext {
    /// Create a new server context
    pub fn new(context: SharedContext, svr_cfg: Arc<ServerConfig>) -> SharedTcpServerContext {
        let stop_flag = Arc::new(AtomicBool::new(false));

        let ctx = TcpServerContext {
            tx: AtomicUsize::new(0),
            rx: AtomicUsize::new(0),
            context,
            stop_flag: stop_flag.clone(),
            svr_cfg,
        };

        let ctx = Arc::new(ctx);

        if ctx.context.config().manager_address.is_some() {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let mut interval = time::interval(UPDATE_INTERVAL);
                loop {
                    interval.tick().await;
                    if stop_flag.load(Ordering::Acquire) {
                        // Finished
                        break;
                    } else {
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            let _ = ctx.stat_interval().await;
                        });
                    }
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
        let addr = match self.context.config().manager_address {
            Some(ServerAddr::SocketAddr(ref addr)) => *addr,
            Some(ServerAddr::DomainName(ref domain, ref port)) => {
                let addrs = resolve(self.context.clone(), &domain[..], *port, false).await?;
                addrs[0]
            }
            None => unreachable!(),
        };

        let svr_cfg = self.svr_cfg.clone();
        let transmission = self.tx.load(Ordering::Acquire) + self.rx.load(Ordering::Acquire);

        let any_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut socket = UdpSocket::bind(&any_addr).await?;

        let payload = format!("stat: {{\"{}\": {}}}", svr_cfg.addr().port(), transmission);
        debug!("Sending Tcp Relay to {}, payload: {}", addr, payload);
        socket.send_to(payload.as_ref(), &addr).await?;

        Ok(())
    }

    pub fn close(&self) {
        self.stop_flag.store(true, Ordering::Release)
    }
}
