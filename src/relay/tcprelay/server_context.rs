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
    // This is a pointer referencing one of the ServerConfig inside context's config (self referencing)
    // And because SharedContext is a Arc<Context>, svr_cfg should have the same lifetime as context.
    // I don't know how to convince rustc that it is safe.
    svr_cfg: *const ServerConfig,
}

unsafe impl Send for TcpServerContext {}
unsafe impl Sync for TcpServerContext {}

const UPDATE_INTERVAL: Duration = Duration::from_secs(5);

pub type SharedTcpServerContext = Arc<TcpServerContext>;

impl TcpServerContext {
    /// Create a new server context
    pub fn new(context: SharedContext, svr_cfg: &ServerConfig) -> SharedTcpServerContext {
        let ctx = TcpServerContext {
            tx: AtomicUsize::new(0),
            rx: AtomicUsize::new(0),
            context,
            svr_cfg: svr_cfg as *const _,
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

    pub fn incr_tx(&self, x: usize) {
        self.tx.fetch_add(x, Ordering::Release);
    }

    pub fn incr_rx(&self, x: usize) {
        self.rx.fetch_add(x, Ordering::Release);
    }

    pub fn svr_cfg(&self) -> &ServerConfig {
        unsafe { &*self.svr_cfg }
    }

    async fn stat_interval(&self) -> io::Result<()> {
        let transmission = self.tx.load(Ordering::Acquire) + self.rx.load(Ordering::Acquire);

        let any_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let mut socket = UdpSocket::bind(&any_addr).await?;

        let payload = format!("stat: {{\"{}\": {}}}", self.svr_cfg().addr().port(), transmission);

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
            ServerAddr::DomainName(ref domain, ref port) => {
                use crate::relay::dns_resolver::resolve;

                let addrs = resolve(&*self.context, &domain[..], *port, false).await?;
                socket.send_to(payload.as_ref(), addrs[0]).await?;
            }
        }

        Ok(())
    }
}
