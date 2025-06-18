//! Shadowsocks Local Server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures::future;
use log::trace;
use shadowsocks::{
    config::Mode,
    net::{AcceptOpts, ConnectOpts},
};

#[cfg(feature = "local-flow-stat")]
use crate::{config::LocalFlowStatAddress, net::FlowStat};
use crate::{
    config::{Config, ConfigType, ProtocolType},
    dns::build_dns_resolver,
    utils::ServerHandle,
};

use self::{
    context::ServiceContext,
    loadbalancing::{PingBalancer, PingBalancerBuilder},
};

#[cfg(feature = "local-dns")]
use self::dns::{Dns, DnsBuilder};
#[cfg(feature = "local-fake-dns")]
use self::fake_dns::{FakeDns, FakeDnsBuilder};
#[cfg(feature = "local-http")]
use self::http::{Http, HttpBuilder};
#[cfg(feature = "local-online-config")]
use self::online_config::{OnlineConfigService, OnlineConfigServiceBuilder};
#[cfg(feature = "local-redir")]
use self::redir::{Redir, RedirBuilder};
use self::socks::{Socks, SocksBuilder};
#[cfg(feature = "local-tun")]
use self::tun::{Tun, TunBuilder};
#[cfg(feature = "local-tunnel")]
use self::tunnel::{Tunnel, TunnelBuilder};

pub mod context;
#[cfg(feature = "local-dns")]
pub mod dns;
#[cfg(feature = "local-fake-dns")]
pub mod fake_dns;
#[cfg(feature = "local-http")]
pub mod http;
pub mod loadbalancing;
pub mod net;
#[cfg(feature = "local-online-config")]
pub mod online_config;
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
    balancer: PingBalancer,
    socks_servers: Vec<Socks>,
    #[cfg(feature = "local-tunnel")]
    tunnel_servers: Vec<Tunnel>,
    #[cfg(feature = "local-http")]
    http_servers: Vec<Http>,
    #[cfg(feature = "local-tun")]
    tun_servers: Vec<Tun>,
    #[cfg(feature = "local-dns")]
    dns_servers: Vec<Dns>,
    #[cfg(feature = "local-redir")]
    redir_servers: Vec<Redir>,
    #[cfg(feature = "local-fake-dns")]
    fake_dns_servers: Vec<FakeDns>,
    #[cfg(feature = "local-flow-stat")]
    local_stat_addr: Option<LocalFlowStatAddress>,
    #[cfg(feature = "local-flow-stat")]
    flow_stat: Arc<FlowStat>,
    #[cfg(feature = "local-online-config")]
    online_config: Option<OnlineConfigService>,
}

impl Server {
    /// Create a shadowsocks local server
    pub async fn new(config: Config) -> io::Result<Self> {
        assert!(config.config_type == ConfigType::Local && !config.local.is_empty());

        trace!("{:?}", config);

        // Warning for Stream Ciphers
        // NOTE: This will only check servers in config.
        #[cfg(feature = "stream-cipher")]
        for inst in config.server.iter() {
            let server = &inst.config;

            if server.method().is_stream() {
                log::warn!(
                    "stream cipher {} for server {} have inherent weaknesses (see discussion in https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                    DO NOT USE. It will be removed in the future.",
                    server.method(),
                    server.addr()
                );
            }
        }

        #[cfg(all(unix, not(target_os = "android")))]
        if let Some(nofile) = config.nofile {
            use crate::sys::set_nofile;
            if let Err(err) = set_nofile(nofile) {
                log::warn!("set_nofile {} failed, error: {}", nofile, err);
            }
        }

        // Global ServiceContext template
        // Each Local instance will hold a copy of its fields
        let mut context = ServiceContext::new();

        let mut connect_opts = ConnectOpts {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            fwmark: config.outbound_fwmark,
            #[cfg(target_os = "freebsd")]
            user_cookie: config.outbound_user_cookie,

            #[cfg(target_os = "android")]
            vpn_protect_path: config.outbound_vpn_protect_path,

            bind_interface: config.outbound_bind_interface,
            bind_local_addr: config.outbound_bind_addr.map(|ip| SocketAddr::new(ip, 0)),

            ..Default::default()
        };
        connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
        connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
        connect_opts.tcp.nodelay = config.no_delay;
        connect_opts.tcp.fastopen = config.fast_open;
        connect_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
        connect_opts.tcp.mptcp = config.mptcp;
        connect_opts.udp.mtu = config.udp_mtu;
        connect_opts.udp.allow_fragmentation = config.outbound_udp_allow_fragmentation;
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
        accept_opts.tcp.mptcp = config.mptcp;
        accept_opts.udp.mtu = config.udp_mtu;
        context.set_accept_opts(accept_opts);

        if let Some(resolver) = build_dns_resolver(
            config.dns,
            config.ipv6_first,
            config.dns_cache_size,
            context.connect_opts_ref(),
        )
        .await
        {
            context.set_dns_resolver(Arc::new(resolver));
        }

        if config.ipv6_first {
            context.set_ipv6_first(config.ipv6_first);
        }

        if let Some(acl) = config.acl {
            context.set_acl(Arc::new(acl));
        }

        context.set_security_config(&config.security);

        assert!(!config.local.is_empty(), "no valid local server configuration");

        // Create a service balancer for choosing between multiple servers
        let balancer = {
            let mut mode: Option<Mode> = None;

            for local in &config.local {
                mode = Some(match mode {
                    None => local.config.mode,
                    Some(m) => m.merge(local.config.mode),
                });
            }

            let mode = mode.unwrap_or(Mode::TcpOnly);

            // Load balancer will hold an individual ServiceContext
            let mut balancer_builder = PingBalancerBuilder::new(Arc::new(context.clone()), mode);

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

        let mut local_server = Self {
            balancer: balancer.clone(),
            socks_servers: Vec::new(),
            #[cfg(feature = "local-tunnel")]
            tunnel_servers: Vec::new(),
            #[cfg(feature = "local-http")]
            http_servers: Vec::new(),
            #[cfg(feature = "local-tun")]
            tun_servers: Vec::new(),
            #[cfg(feature = "local-dns")]
            dns_servers: Vec::new(),
            #[cfg(feature = "local-redir")]
            redir_servers: Vec::new(),
            #[cfg(feature = "local-fake-dns")]
            fake_dns_servers: Vec::new(),
            #[cfg(feature = "local-flow-stat")]
            local_stat_addr: config.local_stat_addr,
            #[cfg(feature = "local-flow-stat")]
            flow_stat: context.flow_stat(),
            #[cfg(feature = "local-online-config")]
            online_config: match config.online_config {
                None => None,
                Some(online_config) => {
                    let mut builder = OnlineConfigServiceBuilder::new(
                        Arc::new(context.clone()),
                        online_config.config_url,
                        balancer.clone(),
                    );
                    if let Some(update_interval) = online_config.update_interval {
                        builder.set_update_interval(update_interval);
                    }
                    Some(builder.build().await?)
                }
            },
        };

        for local_instance in config.local {
            let local_config = local_instance.config;

            // Clone from global ServiceContext instance
            // It will shares Shadowsocks' global context, and FlowStat, DNS reverse cache
            let mut context = context.clone();

            // Private ACL
            if let Some(acl) = local_instance.acl {
                context.set_acl(Arc::new(acl))
            }

            let context = Arc::new(context);
            let balancer = balancer.clone();

            match local_config.protocol {
                ProtocolType::Socks => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("socks requires local address")),
                    };

                    let mut server_builder = SocksBuilder::with_context(context.clone(), client_addr, balancer);
                    server_builder.set_mode(local_config.mode);
                    server_builder.set_socks5_auth(local_config.socks5_auth);

                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    if let Some(b) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(b.clone());
                    }
                    if let Some(b) = local_config.udp_associate_addr {
                        server_builder.set_udp_associate_addr(b.clone());
                    }

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        server_builder.set_launchd_tcp_socket_name(n);
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_udp_socket_name {
                        server_builder.set_launchd_udp_socket_name(n);
                    }

                    let server = server_builder.build().await?;
                    local_server.socks_servers.push(server);
                }
                #[cfg(feature = "local-tunnel")]
                ProtocolType::Tunnel => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("tunnel requires local address")),
                    };

                    let forward_addr = local_config.forward_addr.expect("tunnel requires forward address");

                    let mut server_builder =
                        TunnelBuilder::with_context(context.clone(), forward_addr.clone(), client_addr, balancer);

                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    server_builder.set_mode(local_config.mode);
                    if let Some(udp_addr) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(udp_addr);
                    }

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        server_builder.set_launchd_tcp_socket_name(n);
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_udp_socket_name {
                        server_builder.set_launchd_udp_socket_name(n);
                    }

                    let server = server_builder.build().await?;
                    local_server.tunnel_servers.push(server);
                }
                #[cfg(feature = "local-http")]
                ProtocolType::Http => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("http requires local address")),
                    };

                    #[allow(unused_mut)]
                    let mut builder = HttpBuilder::with_context(context.clone(), client_addr, balancer);

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        builder.set_launchd_tcp_socket_name(n);
                    }

                    let server = builder.build().await?;
                    local_server.http_servers.push(server);
                }
                #[cfg(feature = "local-redir")]
                ProtocolType::Redir => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("redir requires local address")),
                    };

                    let mut server_builder = RedirBuilder::with_context(context.clone(), client_addr, balancer);
                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    server_builder.set_mode(local_config.mode);
                    server_builder.set_tcp_redir(local_config.tcp_redir);
                    server_builder.set_udp_redir(local_config.udp_redir);
                    if let Some(udp_addr) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(udp_addr);
                    }

                    let server = server_builder.build().await?;
                    local_server.redir_servers.push(server);
                }
                #[cfg(feature = "local-dns")]
                ProtocolType::Dns => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("dns requires local address")),
                    };

                    let mut server_builder = {
                        let local_addr = local_config.local_dns_addr.expect("missing local_dns_addr");
                        let remote_addr = local_config.remote_dns_addr.expect("missing remote_dns_addr");
                        let client_cache_size = local_config.client_cache_size.unwrap_or(5);

                        DnsBuilder::with_context(
                            context.clone(),
                            client_addr,
                            local_addr.clone(),
                            remote_addr.clone(),
                            balancer,
                            client_cache_size,
                        )
                    };
                    server_builder.set_mode(local_config.mode);

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        server_builder.set_launchd_tcp_socket_name(n);
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_udp_socket_name {
                        server_builder.set_launchd_udp_socket_name(n);
                    }

                    let server = server_builder.build().await?;
                    local_server.dns_servers.push(server);
                }
                #[cfg(feature = "local-tun")]
                ProtocolType::Tun => {
                    let mut builder = TunBuilder::new(context.clone(), balancer);
                    if let Some(address) = local_config.tun_interface_address {
                        builder.address(address);
                    }
                    if let Some(address) = local_config.tun_interface_destination {
                        builder.destination(address);
                    }
                    if let Some(name) = local_config.tun_interface_name {
                        builder.name(&name);
                    }
                    if let Some(c) = config.udp_max_associations {
                        builder.udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        builder.udp_expiry_duration(d);
                    }
                    builder.mode(local_config.mode);
                    #[cfg(unix)]
                    if let Some(fd) = local_config.tun_device_fd {
                        builder.file_descriptor(fd);
                    } else if let Some(ref fd_path) = local_config.tun_device_fd_from_path {
                        use std::fs;

                        use log::info;
                        use shadowsocks::net::UnixListener;

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

                                    builder.file_descriptor(fd_buffer[0]);
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
                    local_server.tun_servers.push(server);
                }
                #[cfg(feature = "local-fake-dns")]
                ProtocolType::FakeDns => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("dns requires local address")),
                    };

                    let mut builder = FakeDnsBuilder::new(client_addr);
                    if let Some(n) = local_config.fake_dns_ipv4_network {
                        builder.set_ipv4_network(n);
                    }
                    if let Some(n) = local_config.fake_dns_ipv6_network {
                        builder.set_ipv6_network(n);
                    }
                    if let Some(exp) = local_config.fake_dns_record_expire_duration {
                        builder.set_expire_duration(exp);
                    }
                    if let Some(p) = local_config.fake_dns_database_path {
                        builder.set_database_path(p);
                    }
                    let server = builder.build().await?;
                    #[cfg(feature = "local-fake-dns")]
                    context.add_fake_dns_manager(server.clone_manager()).await;

                    local_server.fake_dns_servers.push(server);
                }
            }
        }

        Ok(local_server)
    }

    /// Run local server
    pub async fn run(self) -> io::Result<()> {
        let mut vfut = Vec::new();

        for svr in self.socks_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-tunnel")]
        for svr in self.tunnel_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-http")]
        for svr in self.http_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-tun")]
        for svr in self.tun_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-dns")]
        for svr in self.dns_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-redir")]
        for svr in self.redir_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-fake-dns")]
        for svr in self.fake_dns_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-flow-stat")]
        if let Some(stat_addr) = self.local_stat_addr {
            // For Android's flow statistic

            let report_fut = flow_report_task(stat_addr, self.flow_stat);
            vfut.push(ServerHandle(tokio::spawn(report_fut)));
        }

        #[cfg(feature = "local-online-config")]
        if let Some(online_config) = self.online_config {
            vfut.push(ServerHandle(tokio::spawn(online_config.run())));
        }

        let (res, ..) = future::select_all(vfut).await;
        res
    }

    /// Get the internal server balancer
    pub fn server_balancer(&self) -> &PingBalancer {
        &self.balancer
    }

    /// Get SOCKS server instances
    pub fn socks_servers(&self) -> &[Socks] {
        &self.socks_servers
    }

    /// Get Tunnel server instances
    #[cfg(feature = "local-tunnel")]
    pub fn tunnel_servers(&self) -> &[Tunnel] {
        &self.tunnel_servers
    }

    /// Get HTTP server instances
    #[cfg(feature = "local-http")]
    pub fn http_servers(&self) -> &[Http] {
        &self.http_servers
    }

    /// Get Tun server instances
    #[cfg(feature = "local-tun")]
    pub fn tun_servers(&self) -> &[Tun] {
        &self.tun_servers
    }

    /// Get DNS server instances
    #[cfg(feature = "local-dns")]
    pub fn dns_servers(&self) -> &[Dns] {
        &self.dns_servers
    }

    /// Get Redir server instances
    #[cfg(feature = "local-redir")]
    pub fn redir_servers(&self) -> &[Redir] {
        &self.redir_servers
    }

    /// Get Fake DNS instances
    #[cfg(feature = "local-fake-dns")]
    pub fn fake_dns_servers(&self) -> &[FakeDns] {
        &self.fake_dns_servers
    }
}

#[cfg(feature = "local-flow-stat")]
async fn flow_report_task(stat_addr: LocalFlowStatAddress, flow_stat: Arc<FlowStat>) -> io::Result<()> {
    use std::slice;

    use log::debug;
    use tokio::{io::AsyncWriteExt, time};

    // Local flow statistic report RPC
    let timeout = Duration::from_secs(1);

    loop {
        // keep it as libev's default, 0.5 seconds
        time::sleep(Duration::from_millis(500)).await;

        let tx = flow_stat.tx();
        let rx = flow_stat.rx();

        let buf: [u64; 2] = [tx, rx];
        let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

        match stat_addr {
            #[cfg(unix)]
            LocalFlowStatAddress::UnixStreamPath(ref stat_path) => {
                use tokio::net::UnixStream;

                let mut stream = match time::timeout(timeout, UnixStream::connect(stat_path)).await {
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
            LocalFlowStatAddress::TcpStreamAddr(stat_addr) => {
                use tokio::net::TcpStream;

                let mut stream = match time::timeout(timeout, TcpStream::connect(stat_addr)).await {
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
    }
}

/// Create then run a Local Server
pub async fn run(config: Config) -> io::Result<()> {
    Server::new(config).await?.run().await
}
