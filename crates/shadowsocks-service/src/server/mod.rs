//! Shadowsocks server

use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{future, ready};
use log::trace;
use shadowsocks::net::{AcceptOpts, ConnectOpts};
use tokio::task::JoinHandle;

use crate::{
    config::{Config, ConfigType},
    dns::build_dns_resolver,
};

pub use self::server::Server;

pub mod context;
#[allow(clippy::module_inception)]
pub mod server;
mod tcprelay;
mod udprelay;

/// Default TCP Keep Alive timeout
///
/// This is borrowed from Go's `net` library's default setting
pub(crate) const SERVER_DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Starts a shadowsocks server
pub async fn run(config: Config) -> io::Result<()> {
    assert_eq!(config.config_type, ConfigType::Server);
    assert!(!config.server.is_empty());

    trace!("{:?}", config);

    // Warning for Stream Ciphers
    #[cfg(feature = "stream-cipher")]
    for inst in config.server.iter() {
        let server = &inst.config;

        if server.method().is_stream() {
            log::warn!("stream cipher {} for server {} have inherent weaknesses (see discussion in https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                    DO NOT USE. It will be removed in the future.", server.method(), server.addr());
        }
    }

    #[cfg(all(unix, not(target_os = "android")))]
    if let Some(nofile) = config.nofile {
        use crate::sys::set_nofile;
        if let Err(err) = set_nofile(nofile) {
            log::warn!("set_nofile {} failed, error: {}", nofile, err);
        }
    }

    let mut servers = Vec::new();

    let mut connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        bind_local_addr: config.outbound_bind_addr,
        bind_interface: config.outbound_bind_interface,

        ..Default::default()
    };

    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    connect_opts.tcp.nodelay = config.no_delay;
    connect_opts.tcp.fastopen = config.fast_open;
    connect_opts.tcp.keepalive = config.keep_alive.or(Some(SERVER_DEFAULT_KEEPALIVE_TIMEOUT));

    let mut accept_opts = AcceptOpts {
        ipv6_only: config.ipv6_only,
        ..Default::default()
    };
    accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
    accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
    accept_opts.tcp.nodelay = config.no_delay;
    accept_opts.tcp.fastopen = config.fast_open;
    accept_opts.tcp.keepalive = config.keep_alive.or(Some(SERVER_DEFAULT_KEEPALIVE_TIMEOUT));

    let resolver = build_dns_resolver(config.dns, config.ipv6_first, &connect_opts)
        .await
        .map(Arc::new);

    let acl = config.acl.map(Arc::new);

    for inst in config.server {
        let svr_cfg = inst.config;
        let mut server = Server::new(svr_cfg);

        if let Some(ref r) = resolver {
            server.set_dns_resolver(r.clone());
        }

        server.set_connect_opts(connect_opts.clone());
        server.set_accept_opts(accept_opts.clone());

        if let Some(c) = config.udp_max_associations {
            server.set_udp_capacity(c);
        }
        if let Some(d) = config.udp_timeout {
            server.set_udp_expiry_duration(d);
        }
        if let Some(ref m) = config.manager {
            server.set_manager_addr(m.addr.clone());
        }

        match inst.acl {
            Some(acl) => server.set_acl(Arc::new(acl)),
            None => {
                if let Some(ref acl) = acl {
                    server.set_acl(acl.clone());
                }
            }
        }

        if config.ipv6_first {
            server.set_ipv6_first(config.ipv6_first);
        }

        if config.worker_count >= 1 {
            server.set_worker_count(config.worker_count);
        }

        server.set_security_config(&config.security);

        servers.push(server);
    }

    if servers.len() == 1 {
        let server = servers.pop().unwrap();
        return server.run().await;
    }

    let mut vfut = Vec::with_capacity(servers.len());

    for server in servers {
        vfut.push(ServerHandle(tokio::spawn(async move { server.run().await })));
    }

    let (res, ..) = future::select_all(vfut).await;
    res
}

struct ServerHandle(JoinHandle<io::Result<()>>);

impl Drop for ServerHandle {
    #[inline]
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Future for ServerHandle {
    type Output = io::Result<()>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match ready!(Pin::new(&mut self.0).poll(cx)) {
            Ok(res) => res.into(),
            Err(err) => Err(io::Error::new(ErrorKind::Other, err)).into(),
        }
    }
}
