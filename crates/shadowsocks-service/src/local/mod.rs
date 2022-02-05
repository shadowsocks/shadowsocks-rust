//! Shadowsocks Local Server

#[cfg(feature = "local-flow-stat")]
use std::path::PathBuf;
use std::{
    io::{self, ErrorKind},
    sync::Arc,
    time::Duration,
};

use futures::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
    FutureExt,
};
use log::trace;
use shadowsocks::{
    config::Mode,
    net::{AcceptOpts, ConnectOpts},
};

#[cfg(feature = "local-flow-stat")]
use crate::net::FlowStat;
use crate::{
    config::{Config, ConfigType, ProtocolType},
    dns::build_dns_resolver,
};

use self::{
    context::ServiceContext,
    loadbalancing::{PingBalancer, PingBalancerBuilder},
};

pub mod context;
#[cfg(feature = "local-dns")]
pub mod dns;
#[cfg(feature = "local-http")]
pub mod http;
pub mod loadbalancing;
pub mod net;
#[cfg(feature = "local-redir")]
pub mod redir;
pub mod socks;
#[cfg(feature = "local-tun")]
pub mod tun;
#[cfg(feature = "local-tunnel")]
pub mod tunnel;
pub mod utils;

/// Default TCP Keep Alive timeout
///
/// This is borrowed from Go's `net` library's default setting
pub(crate) const LOCAL_DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Local Server instance
pub struct Server {
    vfut: FuturesUnordered<BoxFuture<'static, io::Result<()>>>,
    balancer: PingBalancer,
}

impl Server {
    /// Run local server
    pub async fn run(self) -> io::Result<()> {
        let (res, _) = self.vfut.into_future().await;
        res.unwrap()
    }

    /// Get the internal server balancer
    pub fn server_balancer(&self) -> &PingBalancer {
        &self.balancer
    }
}

/// Starts a shadowsocks local server
pub async fn create(config: Config) -> io::Result<Server> {
    assert!(config.config_type == ConfigType::Local && !config.local.is_empty());
    assert!(!config.server.is_empty());

    trace!("{:?}", config);

    // Warning for Stream Ciphers
    #[cfg(feature = "stream-cipher")]
    for server in config.server.iter() {
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

    let mut context = ServiceContext::new();

    let mut connect_opts = ConnectOpts {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fwmark: config.outbound_fwmark,

        #[cfg(target_os = "android")]
        vpn_protect_path: config.outbound_vpn_protect_path,

        bind_interface: config.outbound_bind_interface,
        bind_local_addr: config.outbound_bind_addr,

        ..Default::default()
    };
    connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
    connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
    connect_opts.tcp.nodelay = config.no_delay;
    connect_opts.tcp.fastopen = config.fast_open;
    connect_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
    context.set_connect_opts(connect_opts);

    let mut accept_opts = AcceptOpts {
        ipv6_only: config.ipv6_only,
        ..Default::default()
    };
    accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
    accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
    accept_opts.tcp.nodelay = config.no_delay;
    accept_opts.tcp.fastopen = config.fast_open;
    accept_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
    context.set_accept_opts(accept_opts);

    if let Some(resolver) = build_dns_resolver(config.dns, config.ipv6_first, context.connect_opts_ref()).await {
        context.set_dns_resolver(Arc::new(resolver));
    }

    if config.ipv6_first {
        context.set_ipv6_first(config.ipv6_first);
    }

    if let Some(acl) = config.acl {
        context.set_acl(acl);
    }

    context.set_security_config(&config.security);

    assert!(!config.local.is_empty(), "no valid local server configuration");

    let context = Arc::new(context);

    let vfut = FuturesUnordered::new();

    // Create a service balancer for choosing between multiple servers
    let balancer = {
        let mut mode = Mode::TcpOnly;

        for local in &config.local {
            mode = mode.merge(local.mode);
        }

        let mut balancer_builder = PingBalancerBuilder::new(context.clone(), mode);

        // max_server_rtt have to be set before add_server
        if let Some(rtt) = config.balancer.max_server_rtt {
            balancer_builder.max_server_rtt(rtt);
        }

        if let Some(intv) = config.balancer.check_interval {
            balancer_builder.check_interval(intv);
        }

        if let Some(intv) = config.balancer.check_best_interval {
            balancer_builder.check_best_interval(intv);
        }

        for server in config.server {
            balancer_builder.add_server(server);
        }

        balancer_builder.build().await?
    };

    #[cfg(feature = "local-flow-stat")]
    if let Some(stat_path) = config.stat_path {
        // For Android's flow statistic

        let report_fut = flow_report_task(stat_path, context.flow_stat());
        vfut.push(report_fut.boxed());
    }

    for local_config in config.local {
        let balancer = balancer.clone();

        match local_config.protocol {
            ProtocolType::Socks => {
                use self::socks::Socks;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "socks requires local address")),
                };

                let mut server = Socks::with_context(context.clone());
                server.set_mode(local_config.mode);

                if let Some(c) = config.udp_max_associations {
                    server.set_udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    server.set_udp_expiry_duration(d);
                }
                if let Some(b) = local_config.udp_addr {
                    server.set_udp_bind_addr(b.clone());
                }

                vfut.push(async move { server.run(&client_addr, balancer).await }.boxed());
            }
            #[cfg(feature = "local-tunnel")]
            ProtocolType::Tunnel => {
                use self::tunnel::Tunnel;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "tunnel requires local address")),
                };

                let forward_addr = local_config.forward_addr.expect("tunnel requires forward address");

                let mut server = Tunnel::with_context(context.clone(), forward_addr.clone());

                if let Some(c) = config.udp_max_associations {
                    server.set_udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    server.set_udp_expiry_duration(d);
                }
                server.set_mode(local_config.mode);

                let udp_addr = local_config.udp_addr.unwrap_or_else(|| client_addr.clone());
                vfut.push(async move { server.run(&client_addr, &udp_addr, balancer).await }.boxed());
            }
            #[cfg(feature = "local-http")]
            ProtocolType::Http => {
                use self::http::Http;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "http requires local address")),
                };

                let server = Http::with_context(context.clone());
                vfut.push(async move { server.run(&client_addr, balancer).await }.boxed());
            }
            #[cfg(feature = "local-redir")]
            ProtocolType::Redir => {
                use self::redir::Redir;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "redir requires local address")),
                };

                let mut server = Redir::with_context(context.clone());
                if let Some(c) = config.udp_max_associations {
                    server.set_udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    server.set_udp_expiry_duration(d);
                }
                server.set_mode(local_config.mode);
                server.set_tcp_redir(local_config.tcp_redir);
                server.set_udp_redir(local_config.udp_redir);

                let udp_addr = local_config.udp_addr.unwrap_or_else(|| client_addr.clone());
                vfut.push(async move { server.run(&client_addr, &udp_addr, balancer).await }.boxed());
            }
            #[cfg(feature = "local-dns")]
            ProtocolType::Dns => {
                use self::dns::Dns;

                let client_addr = match local_config.addr {
                    Some(a) => a,
                    None => return Err(io::Error::new(ErrorKind::Other, "dns requires local address")),
                };

                let mut server = {
                    let local_addr = local_config.local_dns_addr.expect("missing local_dns_addr");
                    let remote_addr = local_config.remote_dns_addr.expect("missing remote_dns_addr");

                    Dns::with_context(context.clone(), local_addr.clone(), remote_addr.clone())
                };
                server.set_mode(local_config.mode);

                vfut.push(async move { server.run(&client_addr, balancer).await }.boxed());
            }
            #[cfg(feature = "local-tun")]
            ProtocolType::Tun => {
                use log::info;
                use shadowsocks::net::UnixListener;

                use self::tun::TunBuilder;

                let mut builder = TunBuilder::new(context.clone(), balancer);
                if let Some(address) = local_config.tun_interface_address {
                    builder = builder.address(address);
                }
                if let Some(name) = local_config.tun_interface_name {
                    builder = builder.name(&name);
                }
                if let Some(c) = config.udp_max_associations {
                    builder = builder.udp_capacity(c);
                }
                if let Some(d) = config.udp_timeout {
                    builder = builder.udp_expiry_duration(d);
                }
                builder = builder.mode(local_config.mode);
                #[cfg(unix)]
                if let Some(fd) = local_config.tun_device_fd {
                    builder = builder.file_descriptor(fd);
                } else if let Some(ref fd_path) = local_config.tun_device_fd_from_path {
                    use std::fs;

                    let _ = fs::remove_file(fd_path);

                    let listener = match UnixListener::bind(fd_path) {
                        Ok(l) => l,
                        Err(err) => {
                            log::error!("failed to bind uds path \"{}\", error: {}", fd_path.display(), err);
                            return Err(err);
                        }
                    };

                    info!("waiting tun's file descriptor from {}", fd_path.display());

                    loop {
                        let (mut stream, peer_addr) = listener.accept().await?;
                        trace!("accepted {:?} for receiving tun file descriptor", peer_addr);

                        let mut buffer = [0u8; 1024];
                        let mut fd_buffer = [0];

                        match stream.recv_with_fd(&mut buffer, &mut fd_buffer).await {
                            Ok((n, fd_size)) => {
                                if fd_size == 0 {
                                    log::error!(
                                        "client {:?} didn't send file descriptors with buffer.size {} bytes",
                                        peer_addr,
                                        n
                                    );
                                    continue;
                                }

                                info!("got file descriptor {} for tun from {:?}", fd_buffer[0], peer_addr);

                                builder = builder.file_descriptor(fd_buffer[0]);
                                break;
                            }
                            Err(err) => {
                                log::error!(
                                    "failed to receive file descriptors from {:?}, error: {}",
                                    peer_addr,
                                    err
                                );
                            }
                        }
                    }
                }
                let server = builder.build().await?;
                vfut.push(async move { server.run().await }.boxed());
            }
        }
    }

    // let (res, ..) = future::select_all(vfut).await;
    // let (res, _) = vfut.into_future().await;
    // res.unwrap()

    Ok(Server { vfut, balancer })
}

#[cfg(feature = "local-flow-stat")]
async fn flow_report_task(stat_path: PathBuf, flow_stat: Arc<FlowStat>) -> io::Result<()> {
    use std::slice;

    use log::debug;
    use tokio::{io::AsyncWriteExt, net::UnixStream, time};

    // Android's flow statistic report RPC
    let timeout = Duration::from_secs(1);

    loop {
        // keep it as libev's default, 0.5 seconds
        time::sleep(Duration::from_millis(500)).await;
        let mut stream = match time::timeout(timeout, UnixStream::connect(&stat_path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(err)) => {
                debug!("send client flow statistic error: {}", err);
                continue;
            }
            Err(..) => {
                debug!("send client flow statistic error: timeout");
                continue;
            }
        };

        let tx = flow_stat.tx();
        let rx = flow_stat.rx();

        let buf: [u64; 2] = [tx as u64, rx as u64];
        let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

        match time::timeout(timeout, stream.write_all(buf)).await {
            Ok(Ok(..)) => {}
            Ok(Err(err)) => {
                debug!("send client flow statistic error: {}", err);
            }
            Err(..) => {
                debug!("send client flow statistic error: timeout");
            }
        }
    }
}

/// Create then run a Local Server
pub async fn run(config: Config) -> io::Result<()> {
    create(config).await?.run().await
}
