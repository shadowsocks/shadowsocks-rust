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
    relay::{boxed_future, dns_resolver::resolve},
};

use futures::{future, Future, Stream};
use log::debug;
use tokio::{self, net::UdpSocket, timer::Interval};

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
            let ctx2 = ctx.clone();

            let fut = Interval::new_interval(UPDATE_INTERVAL)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("timer error: {}", e)))
                .for_each(move |_| {
                    let ctx = ctx2.clone();
                    if stop_flag.load(Ordering::Acquire) {
                        // Finished
                        Err(io::Error::new(io::ErrorKind::Other, "server terminated"))
                    } else {
                        tokio::spawn(ctx.stat_interval().map_err(|_| ()));
                        Ok(())
                    }
                });
            tokio::spawn(fut.map_err(|_| ()));
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

    fn stat_interval(&self) -> impl Future<Item = (), Error = io::Error> + Send {
        let addr_fut = match self.context.config().manager_address {
            Some(ServerAddr::SocketAddr(ref addr)) => boxed_future(future::ok(*addr)),
            Some(ServerAddr::DomainName(ref domain, ref port)) => {
                let fut = resolve(self.context.clone(), &domain[..], *port, false).map(|vec_ipaddr| vec_ipaddr[0]);
                boxed_future(fut)
            }
            None => unreachable!(),
        };

        let svr_cfg = self.svr_cfg.clone();
        let transmission = self.tx.load(Ordering::Acquire) + self.rx.load(Ordering::Acquire);

        addr_fut
            .and_then(move |addr| {
                let any_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
                UdpSocket::bind(&any_addr).map(move |socket| (socket, addr))
            })
            .and_then(move |(socket, addr)| {
                let payload = format!("stat: {{\"{}\": {}}}", svr_cfg.addr().port(), transmission);
                debug!("Sending Tcp Relay to {}, payload: {}", addr, payload);
                socket.send_dgram(payload, &addr).map(|_| ())
            })
    }

    pub fn close(&self) {
        self.stop_flag.store(true, Ordering::Release)
    }
}
