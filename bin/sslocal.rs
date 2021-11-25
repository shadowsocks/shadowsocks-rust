//! This is a binary running in the local environment
//!
//! You have to provide all needed configuration attributes via command line parameters,
//! or you could specify a configuration file. The format of configuration file is defined
//! in mod `config`.

use std::{net::IpAddr, path::PathBuf, process, time::Duration};

use clap::{clap_app, Arg, Error as ClapError, ErrorKind as ClapErrorKind};
use futures::future::{self, Either};
use log::info;
use tokio::{self, runtime::Builder};

#[cfg(feature = "local-redir")]
use shadowsocks_service::config::RedirType;
#[cfg(any(feature = "local-dns", feature = "local-tunnel"))]
use shadowsocks_service::shadowsocks::relay::socks5::Address;
use shadowsocks_service::{
    acl::AccessControl,
    config::{Config, ConfigType, LocalConfig, ProtocolType},
    create_local,
    local::loadbalancing::PingBalancer,
    shadowsocks::{
        config::{Mode, ServerAddr, ServerConfig},
        crypto::v1::{available_ciphers, CipherKind},
        plugin::PluginConfig,
    },
};

#[cfg(feature = "logging")]
use self::common::logging;
use self::common::{monitor, validator};

mod common;

/// shadowsocks version
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let (config, runtime) = {
        let mut app = clap_app!(shadowsocks =>
            (version: VERSION)
            (about: "A fast tunnel proxy that helps you bypass firewalls.")

            (@arg CONFIG: -c --config +takes_value "Shadowsocks configuration file (https://shadowsocks.org/en/config/quick-guide.html)")

            (@arg LOCAL_ADDR: -b --("local-addr") +takes_value {validator::validate_server_addr} "Local address, listen only to this address if specified")
            (@arg UDP_ONLY: -u conflicts_with[TCP_AND_UDP] requires[LOCAL_ADDR] "Server mode UDP_ONLY")
            (@arg TCP_AND_UDP: -U requires[LOCAL_ADDR] "Server mode TCP_AND_UDP")
            (@arg PROTOCOL: --protocol +takes_value possible_values(ProtocolType::available_protocols()) "Protocol for communicating with clients (SOCKS5 by default)")
            (@arg UDP_BIND_ADDR: --("udp-bind-addr") +takes_value requires[LOCAL_ADDR] {validator::validate_server_addr} "UDP relay's bind address, default is the same as local-addr")

            (@arg SERVER_ADDR: -s --("server-addr") +takes_value {validator::validate_server_addr} requires[PASSWORD ENCRYPT_METHOD] "Server address")
            (@arg PASSWORD: -k --password +takes_value requires[SERVER_ADDR] "Server's password")
            (@arg ENCRYPT_METHOD: -m --("encrypt-method") +takes_value requires[SERVER_ADDR] possible_values(available_ciphers()) "Server's encryption method")
            (@arg TIMEOUT: --timeout +takes_value {validator::validate_u64} requires[SERVER_ADDR] "Server's timeout seconds for TCP relay")

            (@arg PLUGIN: --plugin +takes_value requires[SERVER_ADDR] "SIP003 (https://shadowsocks.org/en/spec/Plugin.html) plugin")
            (@arg PLUGIN_OPT: --("plugin-opts") +takes_value requires[PLUGIN] "Set SIP003 plugin options")

            (@arg URL: --("server-url") +takes_value {validator::validate_server_url} "Server address in SIP002 (https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html) URL")

            (@group SERVER_CONFIG =>
                (@attributes +multiple arg[SERVER_ADDR URL]))

            (@arg ACL: --acl +takes_value "Path to ACL (Access Control List)")
            (@arg DNS: --dns +takes_value "DNS nameservers, formatted like [(tcp|udp)://]host[:port][,host[:port]]..., or unix:///path/to/dns, or predefined keys like \"google\", \"cloudflare\"")

            (@arg TCP_NO_DELAY: --("tcp-no-delay") !takes_value alias("no-delay") "Set TCP_NODELAY option for socket")
            (@arg TCP_FAST_OPEN: --("tcp-fast-open") !takes_value alias("fast-open") "Enable TCP Fast Open (TFO)")
            (@arg TCP_KEEP_ALIVE: --("tcp-keep-alive") +takes_value {validator::validate_u64} "Set TCP keep alive timeout seconds")

            (@arg UDP_TIMEOUT: --("udp-timeout") +takes_value {validator::validate_u64} "Timeout seconds for UDP relay")
            (@arg UDP_MAX_ASSOCIATIONS: --("udp-max-associations") +takes_value {validator::validate_u64} "Maximum associations to be kept simultaneously for UDP relay")

            (@arg INBOUND_SEND_BUFFER_SIZE: --("inbound-send-buffer-size") +takes_value {validator::validate_u32} "Set inbound sockets' SO_SNDBUF option")
            (@arg INBOUND_RECV_BUFFER_SIZE: --("inbound-recv-buffer-size") +takes_value {validator::validate_u32} "Set inbound sockets' SO_RCVBUF option")
            (@arg OUTBOUND_SEND_BUFFER_SIZE: --("outbound-send-buffer-size") +takes_value {validator::validate_u32} "Set outbound sockets' SO_SNDBUF option")
            (@arg OUTBOUND_RECV_BUFFER_SIZE: --("outbound-recv-buffer-size") +takes_value {validator::validate_u32} "Set outbound sockets' SO_RCVBUF option")

            (@arg OUTBOUND_BIND_ADDR: --("outbound-bind-addr") +takes_value alias("bind-addr") {validator::validate_ip_addr} "Bind address, outbound socket will bind this address")
            (@arg OUTBOUND_BIND_INTERFACE: --("outbound-bind-interface") +takes_value "Set SO_BINDTODEVICE / IP_BOUND_IF / IP_UNICAST_IF option for outbound socket")
        );

        // FIXME: -6 is not a identifier, so we cannot build it with clap_app!
        app = app.arg(
            Arg::with_name("IPV6_FIRST")
                .short("6")
                .help("Resolve hostname to IPv6 address first"),
        );

        #[cfg(feature = "logging")]
        {
            app = clap_app!(@app (app)
                (@arg VERBOSE: -v ... "Set log level")
                (@arg LOG_WITHOUT_TIME: --("log-without-time") "Log without datetime prefix")
                (@arg LOG_CONFIG: --("log-config") +takes_value "log4rs configuration file")
            );
        }

        #[cfg(feature = "local-tunnel")]
        {
            app = clap_app!(@app (app)
                (@arg FORWARD_ADDR: -f --("forward-addr") +takes_value requires[LOCAL_ADDR] {validator::validate_address} required_if("PROTOCOL", "tunnel") "Forwarding data directly to this address (for tunnel)")
            );
        }

        #[cfg(all(unix, not(target_os = "android")))]
        {
            app = clap_app!(@app (app)
                (@arg NOFILE: -n --nofile +takes_value "Set RLIMIT_NOFILE with both soft and hard limit")
            );
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            app = clap_app!(@app (app)
                (@arg OUTBOUND_FWMARK: --("outbound-fwmark") +takes_value {validator::validate_u32} "Set SO_MARK option for outbound socket")
            );
        }

        #[cfg(feature = "local-redir")]
        {
            if RedirType::tcp_default() != RedirType::NotSupported {
                app = clap_app!(@app (app)
                    (@arg TCP_REDIR: --("tcp-redir") +takes_value requires[LOCAL_ADDR] possible_values(RedirType::tcp_available_types()) "TCP redir (transparent proxy) type")
                );
            }

            if RedirType::udp_default() != RedirType::NotSupported {
                app = clap_app!(@app (app)
                    (@arg UDP_REDIR: --("udp-redir") +takes_value requires[LOCAL_ADDR] possible_values(RedirType::udp_available_types()) "UDP redir (transparent proxy) type")
                );
            }
        }

        #[cfg(target_os = "android")]
        {
            app = clap_app!(@app (app)
                (@arg VPN_MODE: --vpn "Enable VPN mode (only for Android)")
            );
        }

        #[cfg(feature = "local-flow-stat")]
        {
            app = clap_app!(@app (app)
                (@arg STAT_PATH: --("stat-path") +takes_value "Specify socket path (unix domain socket) for sending traffic statistic")
            );
        }

        #[cfg(feature = "local-dns")]
        {
            app = clap_app!(@app (app)
                (@arg LOCAL_DNS_ADDR: --("local-dns-addr") +takes_value required_if("PROTOCOL", "dns") requires[LOCAL_ADDR] {validator::validate_name_server_addr} "Specify the address of local DNS server, send queries directly")
                (@arg REMOTE_DNS_ADDR: --("remote-dns-addr") +takes_value required_if("PROTOCOL", "dns") requires[LOCAL_ADDR] {validator::validate_address} "Specify the address of remote DNS server, send queries through shadowsocks' tunnel")

            );

            #[cfg(target_os = "android")]
            {
                app = clap_app!(@app (app)
                    (@arg DNS_LOCAL_ADDR: --("dns-addr") +takes_value requires_all(&["LOCAL_ADDR", "REMOTE_DNS_ADDR"]) {validator::validate_server_addr} "DNS address, listen to this address if specified")
                );
            }
        }

        #[cfg(feature = "local-tun")]
        {
            app = clap_app!(@app (app)
                (@arg TUN_INTERFACE_NAME: --("tun-interface-name") +takes_value "Tun interface name, allocate one if not specify")
                (@arg TUN_INTERFACE_ADDRESS: --("tun-interface-address") +takes_value {validator::validate_ipnet} "Tun interface address (network)")
            );

            #[cfg(unix)]
            {
                app = clap_app!(@app (app)
                    (@arg TUN_DEVICE_FD_FROM_PATH: --("tun-device-fd-from-path") +takes_value "Tun device file descriptor will be transferred from this unix domain socket path")
                );
            }
        }

        #[cfg(unix)]
        {
            app = clap_app!(@app (app)
                (@arg DAEMONIZE: -d --("daemonize") "Daemonize")
                (@arg DAEMONIZE_PID_PATH: --("daemonize-pid") +takes_value "File path to store daemonized process's PID")
            );
        }

        #[cfg(feature = "multi-threaded")]
        {
            app = clap_app!(@app (app)
                (@arg SINGLE_THREADED: --("single-threaded") "Run the program all in one thread")
                (@arg WORKER_THREADS: --("worker-threads") +takes_value {validator::validate_usize} "Sets the number of worker threads the `Runtime` will use")
            );
        }

        let matches = app.get_matches();

        #[cfg(feature = "logging")]
        match matches.value_of("LOG_CONFIG") {
            Some(path) => {
                logging::init_with_file(path);
            }
            None => {
                logging::init_with_config("sslocal", &matches);
            }
        }

        let config_path_opt = matches.value_of("CONFIG").map(|c| PathBuf::from(c)).or_else(|| {
            if !matches.is_present("SERVER_CONFIG") {
                common::config::get_default_config_path()
            } else {
                None
            }
        });

        let mut config = match config_path_opt {
            Some(cpath) => match Config::load_from_file(&cpath, ConfigType::Local) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("loading config \"{}\", {}", cpath.display(), err);
                    process::exit(common::EXIT_CODE_LOAD_CONFIG_FAILURE);
                }
            },
            None => Config::new(ConfigType::Local),
        };

        if let Some(svr_addr) = matches.value_of("SERVER_ADDR") {
            let password = matches.value_of("PASSWORD").expect("password");
            let method = matches
                .value_of("ENCRYPT_METHOD")
                .expect("encrypt-method")
                .parse::<CipherKind>()
                .expect("encryption method");
            let svr_addr = svr_addr.parse::<ServerAddr>().expect("server-addr");

            let timeout = matches
                .value_of("TIMEOUT")
                .map(|t| t.parse::<u64>().expect("timeout"))
                .map(Duration::from_secs);

            let mut sc = ServerConfig::new(svr_addr, password.to_owned(), method);
            if let Some(timeout) = timeout {
                sc.set_timeout(timeout);
            }

            if let Some(p) = matches.value_of("PLUGIN") {
                let plugin = PluginConfig {
                    plugin: p.to_owned(),
                    plugin_opts: matches.value_of("PLUGIN_OPT").map(ToOwned::to_owned),
                    plugin_args: Vec::new(),
                };

                sc.set_plugin(plugin);
            }

            config.server.push(sc);
        }

        if let Some(url) = matches.value_of("URL") {
            let svr_addr = url.parse::<ServerConfig>().expect("server SIP002 url");
            config.server.push(svr_addr);
        }

        #[cfg(feature = "local-flow-stat")]
        {
            if let Some(stat_path) = matches.value_of("STAT_PATH") {
                config.stat_path = Some(From::from(stat_path));
            }
        }

        #[cfg(target_os = "android")]
        if matches.is_present("VPN_MODE") {
            // A socket `protect_path` in CWD
            // Same as shadowsocks-libev's android.c
            config.outbound_vpn_protect_path = Some(From::from("protect_path"));
        }

        if matches.value_of("LOCAL_ADDR").is_some() || matches.value_of("PROTOCOL").is_some() {
            let protocol = match matches.value_of("PROTOCOL") {
                Some("socks") => ProtocolType::Socks,
                #[cfg(feature = "local-http")]
                Some("http") => ProtocolType::Http,
                #[cfg(feature = "local-tunnel")]
                Some("tunnel") => ProtocolType::Tunnel,
                #[cfg(feature = "local-redir")]
                Some("redir") => ProtocolType::Redir,
                #[cfg(feature = "local-dns")]
                Some("dns") => ProtocolType::Dns,
                #[cfg(feature = "local-tun")]
                Some("tun") => ProtocolType::Tun,
                Some(p) => panic!("not supported `protocol` \"{}\"", p),
                None => ProtocolType::Socks,
            };

            let mut local_config = LocalConfig::new(protocol);
            match (protocol, matches.value_of("LOCAL_ADDR")) {
                #[cfg(feature = "local-tun")]
                (ProtocolType::Tun, local_addr_opt) => {
                    if let Some(local_addr) = local_addr_opt {
                        local_config.addr = Some(local_addr.parse::<ServerAddr>().expect("local bind addr"));
                    }
                }
                (_, None) => {
                    ClapError::with_description(
                        format!("Protocol \"{}\" requires local-addr", protocol.as_str()).as_str(),
                        ClapErrorKind::ArgumentNotFound,
                    )
                    .exit();
                }
                (_, Some(local_addr)) => {
                    local_config.addr = Some(local_addr.parse::<ServerAddr>().expect("local bind addr"));
                }
            }

            if let Some(udp_bind_addr) = matches.value_of("UDP_BIND_ADDR") {
                local_config.udp_addr = Some(udp_bind_addr.parse::<ServerAddr>().expect("udp-bind-addr"));
            }

            #[cfg(feature = "local-tunnel")]
            if let Some(faddr) = matches.value_of("FORWARD_ADDR") {
                let addr = faddr.parse::<Address>().expect("forward-addr");
                local_config.forward_addr = Some(addr);
            }

            #[cfg(feature = "local-redir")]
            {
                if let Some(tcp_redir) = matches.value_of("TCP_REDIR") {
                    local_config.tcp_redir = tcp_redir.parse::<RedirType>().expect("TCP redir type");
                }

                if let Some(udp_redir) = matches.value_of("UDP_REDIR") {
                    local_config.udp_redir = udp_redir.parse::<RedirType>().expect("UDP redir type");
                }
            }

            #[cfg(feature = "local-dns")]
            {
                use shadowsocks_service::{local::dns::NameServerAddr, shadowsocks::relay::socks5::AddressError};
                use std::net::SocketAddr;

                #[inline]
                fn parse_remote_dns_addr(a: &str) -> Result<Address, AddressError> {
                    if let Ok(ip) = a.parse::<IpAddr>() {
                        return Ok(Address::SocketAddress(SocketAddr::new(ip, 53)));
                    }

                    if let Ok(saddr) = a.parse::<SocketAddr>() {
                        return Ok(Address::SocketAddress(saddr));
                    }

                    if a.find(':').is_some() {
                        a.parse::<Address>()
                    } else {
                        Ok(Address::DomainNameAddress(a.to_owned(), 53))
                    }
                }

                if let Some(local_dns_addr) = matches.value_of("LOCAL_DNS_ADDR") {
                    let addr = local_dns_addr.parse::<NameServerAddr>().expect("local dns address");
                    local_config.local_dns_addr = Some(addr);
                }

                if let Some(remote_dns_addr) = matches.value_of("REMOTE_DNS_ADDR") {
                    let addr = parse_remote_dns_addr(remote_dns_addr).expect("remote dns address");
                    local_config.remote_dns_addr = Some(addr);
                }
            }

            #[cfg(all(feature = "local-dns", target_os = "android"))]
            if protocol != ProtocolType::Dns {
                // Start a DNS local server binding to DNS_LOCAL_ADDR
                //
                // This is a special route only for shadowsocks-android
                if let Some(dns_relay_addr) = matches.value_of("DNS_LOCAL_ADDR") {
                    let addr = dns_relay_addr.parse::<ServerAddr>().expect("dns relay address");

                    let mut local_dns_config = LocalConfig::new_with_addr(addr, ProtocolType::Dns);

                    // The `local_dns_addr` and `remote_dns_addr` are for this DNS server (for compatibility)
                    local_dns_config.local_dns_addr = local_config.local_dns_addr.take();
                    local_dns_config.remote_dns_addr = local_config.remote_dns_addr.take();

                    config.local.push(local_dns_config);
                }
            }

            #[cfg(feature = "local-tun")]
            {
                if let Some(tun_address) = matches.value_of("TUN_INTERFACE_ADDRESS") {
                    local_config.tun_interface_address = Some(tun_address.parse().expect("tun-interface-address"));
                }
                if let Some(tun_name) = matches.value_of("TUN_INTERFACE_NAME") {
                    local_config.tun_interface_name = Some(tun_name.to_owned());
                }

                #[cfg(unix)]
                if let Some(fd_path) = matches.value_of("TUN_DEVICE_FD_FROM_PATH") {
                    local_config.tun_device_fd_from_path = Some(fd_path.into());
                }
            }

            if matches.is_present("UDP_ONLY") {
                local_config.mode = Mode::UdpOnly;
            }

            if matches.is_present("TCP_AND_UDP") {
                local_config.mode = Mode::TcpAndUdp;
            }

            config.local.push(local_config);
        }

        if matches.is_present("TCP_NO_DELAY") {
            config.no_delay = true;
        }

        if matches.is_present("TCP_FAST_OPEN") {
            config.fast_open = true;
        }

        if let Some(keep_alive) = matches.value_of("TCP_KEEP_ALIVE") {
            config.keep_alive = Some(Duration::from_secs(
                keep_alive
                    .parse::<u64>()
                    .expect("`tcp-keep-alive` is expecting an integer"),
            ));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(mark) = matches.value_of("OUTBOUND_FWMARK") {
            config.outbound_fwmark = Some(mark.parse::<u32>().expect("an unsigned integer for `outbound-fwmark`"));
        }

        if let Some(iface) = matches.value_of("OUTBOUND_BIND_INTERFACE") {
            config.outbound_bind_interface = Some(iface.to_owned());
        }

        #[cfg(all(unix, not(target_os = "android")))]
        if let Some(nofile) = matches.value_of("NOFILE") {
            config.nofile = Some(nofile.parse::<u64>().expect("an unsigned integer for `nofile`"));
        }

        if let Some(acl_file) = matches.value_of("ACL") {
            let acl = match AccessControl::load_from_file(acl_file) {
                Ok(acl) => acl,
                Err(err) => {
                    eprintln!("loading ACL \"{}\", {}", acl_file, err);
                    process::exit(common::EXIT_CODE_LOAD_ACL_FAILURE);
                }
            };
            config.acl = Some(acl);
        }

        if let Some(dns) = matches.value_of("DNS") {
            config.set_dns_formatted(dns).expect("dns");
        }

        if matches.is_present("IPV6_FIRST") {
            config.ipv6_first = true;
        }

        if let Some(udp_timeout) = matches.value_of("UDP_TIMEOUT") {
            config.udp_timeout = Some(Duration::from_secs(udp_timeout.parse::<u64>().expect("udp-timeout")));
        }

        if let Some(udp_max_assoc) = matches.value_of("UDP_MAX_ASSOCIATIONS") {
            config.udp_max_associations = Some(udp_max_assoc.parse::<usize>().expect("udp-max-associations"));
        }

        if let Some(bs) = matches.value_of("INBOUND_SEND_BUFFER_SIZE") {
            config.inbound_send_buffer_size = Some(bs.parse::<u32>().expect("inbound-send-buffer-size"));
        }
        if let Some(bs) = matches.value_of("INBOUND_RECV_BUFFER_SIZE") {
            config.inbound_recv_buffer_size = Some(bs.parse::<u32>().expect("inbound-recv-buffer-size"));
        }
        if let Some(bs) = matches.value_of("OUTBOUND_SEND_BUFFER_SIZE") {
            config.outbound_send_buffer_size = Some(bs.parse::<u32>().expect("outbound-send-buffer-size"));
        }
        if let Some(bs) = matches.value_of("OUTBOUND_RECV_BUFFER_SIZE") {
            config.outbound_recv_buffer_size = Some(bs.parse::<u32>().expect("outbound-recv-buffer-size"));
        }

        if let Some(bind_addr) = matches.value_of("OUTBOUND_BIND_ADDR") {
            let bind_addr = bind_addr.parse::<IpAddr>().expect("outbound-bind-addr");
            config.outbound_bind_addr = Some(bind_addr);
        }

        // DONE READING options

        if config.local.is_empty() {
            eprintln!(
                "missing `local_address`, consider specifying it by --local-addr command line option, \
             or \"local_address\" and \"local_port\" in configuration file"
            );
            println!("{}", matches.usage());
            return;
        }

        if config.server.is_empty() {
            eprintln!(
                "missing proxy servers, consider specifying it by \
             --server-addr, --encrypt-method, --password command line option, \
                or --server-url command line option, \
                or configuration file, check more details in https://shadowsocks.org/en/config/quick-guide.html"
            );
            println!("{}", matches.usage());
            return;
        }

        if let Err(err) = config.check_integrity() {
            eprintln!("config integrity check failed, {}", err);
            println!("{}", matches.usage());
            return;
        }

        #[cfg(unix)]
        if matches.is_present("DAEMONIZE") || matches.is_present("DAEMONIZE_PID_PATH") {
            use self::common::daemonize;
            daemonize::daemonize(matches.value_of("DAEMONIZE_PID_PATH"));
        }

        info!("shadowsocks local {} build {}", VERSION, common::BUILD_TIME);

        #[cfg(feature = "multi-threaded")]
        let mut builder = if matches.is_present("SINGLE_THREADED") {
            Builder::new_current_thread()
        } else {
            let mut builder = Builder::new_multi_thread();
            if let Some(worker_threads) = matches.value_of("WORKER_THREADS") {
                builder.worker_threads(worker_threads.parse::<usize>().expect("worker-threads"));
            }
            builder
        };
        #[cfg(not(feature = "multi-threaded"))]
        let mut builder = Builder::new_current_thread();

        let runtime = builder.enable_all().build().expect("create tokio Runtime");

        (config, runtime)
    };

    runtime.block_on(async move {
        let config_path = config.config_path.clone();

        let instance = create_local(config).await.expect("create local");

        if let Some(config_path) = config_path {
            launch_reload_server_task(config_path, instance.server_balancer().clone());
        }

        let abort_signal = monitor::create_signal_monitor();
        let server = instance.run();

        tokio::pin!(abort_signal);
        tokio::pin!(server);

        match future::select(server, abort_signal).await {
            // Server future resolved without an error. This should never happen.
            Either::Left((Ok(..), ..)) => {
                eprintln!("server exited unexpectedly");
                process::exit(common::EXIT_CODE_SERVER_EXIT_UNEXPECTEDLY);
            }
            // Server future resolved with error, which are listener errors in most cases
            Either::Left((Err(err), ..)) => {
                eprintln!("server aborted with {}", err);
                process::exit(common::EXIT_CODE_SERVER_ABORTED);
            }
            // The abort signal future resolved. Means we should just exit.
            Either::Right(_) => (),
        }
    });
}

#[cfg(unix)]
fn launch_reload_server_task(config_path: PathBuf, balancer: PingBalancer) {
    use log::error;
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async move {
        let mut sigusr1 = signal(SignalKind::user_defined1()).expect("signal");

        while sigusr1.recv().await.is_some() {
            let config = match Config::load_from_file(&config_path, ConfigType::Local) {
                Ok(c) => c,
                Err(err) => {
                    error!("auto-reload {} failed with error: {}", config_path.display(), err);
                    continue;
                }
            };

            let servers = config.server;
            info!("auto-reload {} with {} servers", config_path.display(), servers.len());

            if let Err(err) = balancer.reset_servers(servers).await {
                error!("auto-reload {} but found error: {}", config_path.display(), err);
            }
        }
    });
}

#[cfg(not(unix))]
fn launch_reload_server_task(_: PathBuf, _: PingBalancer) {}
